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
import hashlib
import json
import random
from unittest import mock

import ddt
from oslo_concurrency import lockutils
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import timeutils

from manila.common import constants
from manila import context
from manila import coordination
from manila.data import rpcapi as data_rpc
from manila import db
from manila.db.sqlalchemy import models
from manila import exception
from manila.message import message_field
from manila import quota
from manila.share import api
from manila.share import drivers_private_data
from manila.share import manager
from manila.share import migration as migration_api
from manila.share import rpcapi
from manila.share import share_types
from manila.share import utils as share_utils
from manila import test
from manila.tests.api import fakes as test_fakes
from manila.tests import db_utils
from manila.tests import fake_notifier
from manila.tests import fake_share as fakes
from manila.tests import fake_utils
from manila.tests import utils as test_utils
from manila.transfer import api as transfer_api
from manila import utils


def fake_replica(**kwargs):
    return fakes.fake_replica(for_manager=True, **kwargs)


class CustomTimeSleepException(Exception):
    pass


class LockedOperationsTestCase(test.TestCase):

    class FakeManager(object):

        @manager.locked_share_replica_operation
        def fake_replica_operation(self, context, replica, share_id=None):
            pass

    def setUp(self):
        super(LockedOperationsTestCase, self).setUp()
        self.manager = self.FakeManager()
        self.fake_context = test_fakes.FakeRequestContext
        self.lock_call = self.mock_object(
            coordination, 'synchronized', mock.Mock(return_value=lambda f: f))

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
        self.share_manager.driver._stats = {
            'share_group_stats': {'consistent_snapshot_support': None},
        }
        self.mock_object(self.share_manager.message_api, 'create')
        self.context = context.get_admin_context()
        self.share_manager.driver.initialized = True
        self.share_manager.host = 'fake_host'
        mock.patch.object(
            lockutils, 'lock', fake_utils.get_fake_lock_context())
        self.synchronized_lock_decorator_call = self.mock_object(
            coordination, 'synchronized', mock.Mock(return_value=lambda f: f))

    def test_share_manager_instance(self):
        fake_service_name = "fake_service"
        importutils_mock = mock.Mock()
        self.mock_object(importutils, "import_object", importutils_mock)
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
        self.assertTrue(importutils_mock.called)
        self.assertTrue(manager.ShareManager._init_hook_drivers.called)

    def test__init_hook_drivers(self):
        fake_service_name = "fake_service"
        importutils_mock = mock.Mock()
        self.mock_object(importutils, "import_object", importutils_mock)
        self.mock_object(drivers_private_data, "DriverPrivateData")
        share_manager = manager.ShareManager(service_name=fake_service_name)
        share_manager.configuration.safe_get = mock.Mock(
            return_value=["Foo", "Bar"])
        self.assertEqual(0, len(share_manager.hooks))
        importutils_mock.reset()

        share_manager._init_hook_drivers()

        self.assertEqual(
            len(share_manager.configuration.safe_get.return_value),
            len(share_manager.hooks))
        importutils_mock.assert_has_calls([
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

    def test_is_service_ready(self):
        self.assertTrue(self.share_manager.is_service_ready())

        # switch it to false and check again
        self.share_manager.driver.initialized = False
        self.assertFalse(self.share_manager.is_service_ready())

    @ddt.data(True, False)
    def test_ensure_driver_resources_driver_needs_to_reapply_rules(
            self, driver_needs_to_reapply_rules):
        old_hash = {'info_hash': '1e5ff444cfdc4a154126ddebc0223ffeae2d10c9'}
        self.mock_object(self.share_manager.db,
                         'backend_info_get',
                         mock.Mock(return_value=old_hash))
        self.mock_object(self.share_manager.driver,
                         'get_backend_info',
                         mock.Mock(return_value={'val': 'tigersgo'}))
        instances, rules = self._setup_init_mocks()
        fake_export_locations = ['fake/path/1', 'fake/path']
        fake_update_instances = {
            instances[0]['id']: {
                'export_locations': fake_export_locations,
                'reapply_access_rules': driver_needs_to_reapply_rules,
            },
            instances[2]['id']: {
                'export_locations': fake_export_locations,
                'reapply_access_rules': driver_needs_to_reapply_rules,
            },
        }
        mock_backend_info_update = self.mock_object(
            self.share_manager.db, 'backend_info_update')
        mock_share_get_all_by_host = self.mock_object(
            self.share_manager.db, 'share_instances_get_all_by_host',
            mock.Mock(return_value=instances))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instances[0], instances[2],
                                                instances[4]]))
        self.mock_object(self.share_manager.db,
                         'share_export_locations_update')
        mock_ensure_shares = self.mock_object(
            self.share_manager.driver, 'ensure_shares',
            mock.Mock(return_value=fake_update_instances))
        self.mock_object(self.share_manager, '_ensure_share_instance_has_pool')
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value='share_server'))
        self.mock_object(self.share_manager,
                         '_get_share_server_dict',
                         mock.Mock(return_value='share_server'))
        mock_reset_rules_method = self.mock_object(
            self.share_manager.access_helper, 'reset_rules_to_queueing_states')
        mock_update_rules_method = self.mock_object(
            self.share_manager.access_helper, 'update_access_rules')

        dict_instances = [self._get_share_instance_dict(
            instance, share_server='share_server') for instance in instances]

        self.share_manager.ensure_driver_resources(self.context)

        exports_update = self.share_manager.db.share_export_locations_update
        mock_backend_info_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            self.share_manager.host,
            '77a1d6fc86295017d9908a4f657dc9e089b3de4b')
        mock_ensure_shares.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            [dict_instances[0], dict_instances[2], dict_instances[4]])
        mock_share_get_all_by_host.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            self.share_manager.host)
        exports_update.assert_has_calls([
            mock.call(mock.ANY, instances[0]['id'], fake_export_locations),
            mock.call(mock.ANY, instances[2]['id'], fake_export_locations),
        ])
        self.share_manager._ensure_share_instance_has_pool.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext),
                      instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext),
                      instances[2]),
        ])
        self.share_manager._get_share_server.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext),
                      instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext),
                      instances[2]),
        ])
        if driver_needs_to_reapply_rules:
            # don't care if share_instance['access_rules_status'] is "syncing"
            mock_reset_rules_method.assert_has_calls([
                mock.call(mock.ANY, instances[0]['id'],
                          reset_active=driver_needs_to_reapply_rules),
                mock.call(mock.ANY, instances[2]['id'],
                          reset_active=driver_needs_to_reapply_rules),
            ])
            mock_update_rules_method.assert_has_calls([
                mock.call(mock.ANY, instances[0]['id'],
                          share_server='share_server'),
                mock.call(mock.ANY, instances[2]['id'],
                          share_server='share_server'),
            ])
        else:
            # none of the share instances in the fake data have syncing rules
            mock_reset_rules_method.assert_not_called()
            (self.share_manager.access_helper.update_access_rules
             .assert_not_called())

    def test_init_host_with_no_shares(self):
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_host',
                         mock.Mock(return_value=[]))

        self.share_manager.init_host()

        self.assertTrue(self.share_manager.driver.initialized)
        (self.share_manager.db.share_instances_get_all_by_host.
            assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    self.share_manager.host))
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        (self.share_manager.driver.check_for_setup_error.
            assert_called_once_with())

    @ddt.data(
        "connection_get_info",
        "migration_cancel",
        "migration_get_progress",
        "migration_complete",
        "migration_start",
        "create_share_instance",
        "manage_share",
        "unmanage_share",
        "delete_share_instance",
        "delete_free_share_servers",
        "delete_expired_share",
        "create_snapshot",
        "delete_snapshot",
        "update_access",
        "_report_driver_status",
        "_execute_periodic_hook",
        "publish_service_capabilities",
        "delete_share_server",
        "extend_share",
        "shrink_share",
        "create_share_group",
        "delete_share_group",
        "create_share_group_snapshot",
        "delete_share_group_snapshot",
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
        # break the endless retry loop
        with mock.patch('tenacity.nap.sleep') as sleep:
            sleep.side_effect = CustomTimeSleepException()
            self.assertRaises(CustomTimeSleepException,
                              self.share_manager.init_host)
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

        with mock.patch('time.sleep') as mock_sleep:
            mock_sleep.side_effect = CustomTimeSleepException()
            self.assertRaises(CustomTimeSleepException,
                              self.share_manager.init_host)

        manager.LOG.exception.assert_called_once_with(
            mock.ANY, "%(name)s@%(host)s" %
            {'name': self.share_manager.driver.__class__.__name__,
             'host': self.share_manager.host})
        self.assertFalse(self.share_manager.driver.initialized)

    def _setup_init_mocks(self, setup_access_rules=True):
        share_type = db_utils.create_share_type()
        instances = [
            db_utils.create_share(id='fake_id_1',
                                  share_type_id=share_type['id'],
                                  status=constants.STATUS_AVAILABLE,
                                  display_name='fake_name_1').instance,
            db_utils.create_share(id='fake_id_2',
                                  share_type_id=share_type['id'],
                                  status=constants.STATUS_ERROR,
                                  display_name='fake_name_2').instance,
            db_utils.create_share(id='fake_id_3',
                                  share_type_id=share_type['id'],
                                  status=constants.STATUS_AVAILABLE,
                                  display_name='fake_name_3').instance,
            db_utils.create_share(
                id='fake_id_4',
                share_type_id=share_type['id'],
                status=constants.STATUS_MIGRATING,
                task_state=constants.TASK_STATE_MIGRATION_IN_PROGRESS,
                display_name='fake_name_4').instance,
            db_utils.create_share(id='fake_id_5',
                                  share_type_id=share_type['id'],
                                  status=constants.STATUS_AVAILABLE,
                                  display_name='fake_name_5').instance,
            db_utils.create_share(
                id='fake_id_6',
                share_type_id=share_type['id'],
                status=constants.STATUS_MIGRATING,
                task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
                display_name='fake_name_6').instance,
            db_utils.create_share(
                id='fake_id_7', share_type_id=share_type['id'],
                status=constants.STATUS_CREATING_FROM_SNAPSHOT,
                display_name='fake_name_7').instance,
        ]

        instances[4]['access_rules_status'] = (
            constants.SHARE_INSTANCE_RULES_SYNCING)

        if not setup_access_rules:
            return instances

        rules = [
            db_utils.create_access(share_id='fake_id_1'),
            db_utils.create_access(share_id='fake_id_3'),
        ]

        return instances, rules

    @ddt.data(("some_hash", {"db_version": "test_version"}),
              ("ddd86ec90923b686597501e2f2431f3af59238c0",
               {"db_version": "test_version"}),
              (None, {"db_version": "test_version"}),
              (None, None))
    @ddt.unpack
    def test_init_host_with_shares_and_rules(
            self, old_backend_info_hash, new_backend_info):

        # initialization of test data
        def raise_share_access_exists(*args, **kwargs):
            raise exception.ShareAccessExists(
                access_type='fake_access_type', access='fake_access')

        new_backend_info_hash = (hashlib.sha1(str(
            sorted(new_backend_info.items())).encode('utf-8')).hexdigest() if
            new_backend_info else None)
        old_backend_info = {'info_hash': old_backend_info_hash}
        share_server = fakes.fake_share_server_get()
        instances, rules = self._setup_init_mocks()
        fake_export_locations = ['fake/path/1', 'fake/path']
        fake_update_instances = {
            instances[0]['id']: {'export_locations': fake_export_locations},
            instances[2]['id']: {'export_locations': fake_export_locations}
        }
        instances[0]['access_rules_status'] = ''
        instances[2]['access_rules_status'] = ''
        self.mock_object(self.share_manager.db,
                         'backend_info_get',
                         mock.Mock(return_value=old_backend_info))
        mock_backend_info_update = self.mock_object(
            self.share_manager.db, 'backend_info_update')
        self.mock_object(self.share_manager.driver, 'get_backend_info',
                         mock.Mock(return_value=new_backend_info))
        mock_share_get_all_by_host = self.mock_object(
            self.share_manager.db, 'share_instances_get_all_by_host',
            mock.Mock(return_value=instances))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instances[0], instances[2],
                                                instances[4]]))
        self.mock_object(self.share_manager.db,
                         'share_export_locations_update')
        mock_ensure_shares = self.mock_object(
            self.share_manager.driver, 'ensure_shares',
            mock.Mock(return_value=fake_update_instances))
        self.mock_object(self.share_manager, '_ensure_share_instance_has_pool')
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager, '_get_share_server_dict',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager, 'publish_service_capabilities',
                         mock.Mock())
        self.mock_object(self.share_manager.access_helper,
                         'reset_rules_to_queueing_states')
        self.mock_object(
            self.share_manager.access_helper,
            'update_access_rules',
            mock.Mock(side_effect=raise_share_access_exists)
        )

        dict_instances = [self._get_share_instance_dict(
            instance, share_server=share_server) for instance in instances]

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        exports_update = self.share_manager.db.share_export_locations_update
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        (self.share_manager.driver.check_for_setup_error.
            assert_called_once_with())

        if new_backend_info_hash == old_backend_info_hash:
            mock_backend_info_update.assert_not_called()
            mock_ensure_shares.assert_not_called()
            mock_share_get_all_by_host.assert_not_called()
        else:
            mock_backend_info_update.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.share_manager.host, new_backend_info_hash)
            self.share_manager.driver.ensure_shares.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                [dict_instances[0], dict_instances[2], dict_instances[4]])
            mock_share_get_all_by_host.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.share_manager.host)
            exports_update.assert_has_calls([
                mock.call(mock.ANY, instances[0]['id'], fake_export_locations),
                mock.call(mock.ANY, instances[2]['id'], fake_export_locations)
            ])
            (self.share_manager._ensure_share_instance_has_pool.
                assert_has_calls([
                    mock.call(utils.IsAMatcher(context.RequestContext),
                              instances[0]),
                    mock.call(utils.IsAMatcher(context.RequestContext),
                              instances[2]),
                ]))
            self.share_manager._get_share_server.assert_has_calls([
                mock.call(utils.IsAMatcher(context.RequestContext),
                          instances[0]),
                mock.call(utils.IsAMatcher(context.RequestContext),
                          instances[2]),
            ])
            (self.share_manager.publish_service_capabilities.
                assert_called_once_with(
                    utils.IsAMatcher(context.RequestContext)))
            (self.share_manager.access_helper.update_access_rules.
             assert_has_calls([
                 mock.call(mock.ANY, instances[0]['id'],
                           share_server=share_server),
                 mock.call(mock.ANY, instances[2]['id'],
                           share_server=share_server),
             ]))

    @ddt.data(("some_hash", {"db_version": "test_version"}),
              ("ddd86ec90923b686597501e2f2431f3af59238c0",
               {"db_version": "test_version"}),
              (None, {"db_version": "test_version"}),
              (None, None))
    @ddt.unpack
    def test_init_host_without_shares_and_rules(
            self, old_backend_info_hash, new_backend_info):

        old_backend_info = {'info_hash': old_backend_info_hash}
        new_backend_info_hash = (hashlib.sha1(str(
            sorted(new_backend_info.items())).encode('utf-8')).hexdigest() if
            new_backend_info else None)
        mock_backend_info_update = self.mock_object(
            self.share_manager.db, 'backend_info_update')
        self.mock_object(
            self.share_manager.db, 'backend_info_get',
            mock.Mock(return_value=old_backend_info))
        self.mock_object(self.share_manager.driver, 'get_backend_info',
                         mock.Mock(return_value=new_backend_info))
        self.mock_object(self.share_manager, 'publish_service_capabilities',
                         mock.Mock())
        mock_ensure_shares = self.mock_object(
            self.share_manager.driver, 'ensure_shares')
        mock_share_instances_get_all_by_host = self.mock_object(
            self.share_manager.db, 'share_instances_get_all_by_host',
            mock.Mock(return_value=[]))

        # call of 'init_host' method
        self.share_manager.init_host()
        if new_backend_info_hash == old_backend_info_hash:
            mock_backend_info_update.assert_not_called()
            mock_ensure_shares.assert_not_called()
            mock_share_instances_get_all_by_host.assert_not_called()
        else:
            mock_backend_info_update.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.share_manager.host, new_backend_info_hash)
            self.share_manager.driver.do_setup.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))
            self.share_manager.db.backend_info_get.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.share_manager.host)
            self.share_manager.driver.get_backend_info.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))
            mock_ensure_shares.assert_not_called()
            mock_share_instances_get_all_by_host.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.share_manager.host)

    @ddt.data(exception.ManilaException, ['fake/path/1', 'fake/path'])
    def test_init_host_with_ensure_share(self, expected_ensure_share_result):
        def raise_NotImplementedError(*args, **kwargs):
            raise NotImplementedError

        instances = self._setup_init_mocks(setup_access_rules=False)
        share_server = fakes.fake_share_server_get()
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_host',
                         mock.Mock(return_value=instances))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instances[0], instances[2],
                                                instances[3]]))
        self.mock_object(
            self.share_manager.driver, 'ensure_shares',
            mock.Mock(side_effect=raise_NotImplementedError))
        self.mock_object(self.share_manager.driver, 'ensure_share',
                         mock.Mock(side_effect=expected_ensure_share_result))
        self.mock_object(
            self.share_manager, '_ensure_share_instance_has_pool')
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager, '_get_share_server_dict',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager, 'publish_service_capabilities')
        self.mock_object(manager.LOG, 'error')
        self.mock_object(manager.LOG, 'info')

        dict_instances = [self._get_share_instance_dict(
            instance, share_server=share_server) for instance in instances]

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        (self.share_manager.db.share_instances_get_all_by_host.
            assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    self.share_manager.host))
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.assert_called_with()
        self.share_manager._ensure_share_instance_has_pool.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        self.share_manager.driver.ensure_shares.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            [dict_instances[0], dict_instances[2], dict_instances[3]])
        self.share_manager._get_share_server.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        self.share_manager.driver.ensure_share.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext),
                      dict_instances[0],
                      share_server=share_server),
            mock.call(utils.IsAMatcher(context.RequestContext),
                      dict_instances[2],
                      share_server=share_server),
        ])
        (self.share_manager.publish_service_capabilities.
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext)))
        manager.LOG.info.assert_any_call(
            mock.ANY,
            {'task': constants.TASK_STATE_MIGRATION_IN_PROGRESS,
             'id': instances[3]['id']},
        )
        manager.LOG.info.assert_any_call(
            mock.ANY,
            {'id': instances[1]['id'], 'status': instances[1]['status']},
        )

    def _get_share_instance_dict(self, share_instance, **kwargs):
        # TODO(gouthamr): remove method when the db layer returns primitives
        share_instance_ref = {
            'id': share_instance.get('id'),
            'name': share_instance.get('name'),
            'share_id': share_instance.get('share_id'),
            'host': share_instance.get('host'),
            'status': share_instance.get('status'),
            'replica_state': share_instance.get('replica_state'),
            'availability_zone_id': share_instance.get('availability_zone_id'),
            'share_network_id': share_instance.get('share_network_id'),
            'share_server_id': share_instance.get('share_server_id'),
            'deleted': share_instance.get('deleted'),
            'terminated_at': share_instance.get('terminated_at'),
            'launched_at': share_instance.get('launched_at'),
            'scheduled_at': share_instance.get('scheduled_at'),
            'updated_at': share_instance.get('updated_at'),
            'deleted_at': share_instance.get('deleted_at'),
            'created_at': share_instance.get('created_at'),
            'share_server': kwargs.get('share_server'),
            'access_rules_status': share_instance.get('access_rules_status'),
            # Share details
            'user_id': share_instance.get('user_id'),
            'project_id': share_instance.get('project_id'),
            'size': share_instance.get('size'),
            'display_name': share_instance.get('display_name'),
            'display_description': share_instance.get('display_description'),
            'snapshot_id': share_instance.get('snapshot_id'),
            'share_proto': share_instance.get('share_proto'),
            'share_type_id': share_instance.get('share_type_id'),
            'is_public': share_instance.get('is_public'),
            'share_group_id': share_instance.get('share_group_id'),
            'source_share_group_snapshot_member_id': share_instance.get(
                'source_share_group_snapshot_member_id'),
            'availability_zone': share_instance.get('availability_zone'),
            'export_locations': share_instance.get('export_locations') or [],
        }
        return share_instance_ref

    def test_init_host_with_exception_on_ensure_shares(self):
        def raise_exception(*args, **kwargs):
            raise exception.ManilaException(message="Fake raise")

        instances = self._setup_init_mocks(setup_access_rules=False)
        mock_ensure_share = self.mock_object(
            self.share_manager.driver, 'ensure_share')
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_host',
                         mock.Mock(return_value=instances))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instances[0], instances[2],
                                                instances[3]]))
        self.mock_object(
            self.share_manager.driver, 'ensure_shares',
            mock.Mock(side_effect=raise_exception))
        self.mock_object(
            self.share_manager, '_ensure_share_instance_has_pool')
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value=fakes.fake_share_server_get()))

        dict_instances = [self._get_share_instance_dict(instance)
                          for instance in instances]

        # call of 'init_host' method
        self.share_manager.init_host()

        # verification of call
        (self.share_manager.db.share_instances_get_all_by_host.
         assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                 self.share_manager.host))
        self.share_manager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        self.share_manager.driver.check_for_setup_error.assert_called_with()
        self.share_manager._ensure_share_instance_has_pool.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        self.share_manager.driver.ensure_shares.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            [dict_instances[0], dict_instances[2], dict_instances[3]])
        mock_ensure_share.assert_not_called()

    def test_init_host_with_exception_on_get_backend_info(self):
        def raise_exception(*args, **kwargs):
            raise exception.ManilaException(message="Fake raise")

        old_backend_info = {'info_hash': "test_backend_info"}
        mock_ensure_share = self.mock_object(
            self.share_manager.driver, 'ensure_share')
        mock_ensure_shares = self.mock_object(
            self.share_manager.driver, 'ensure_shares')
        self.mock_object(self.share_manager.db,
                         'backend_info_get',
                         mock.Mock(return_value=old_backend_info))
        self.mock_object(
            self.share_manager.driver, 'get_backend_info',
            mock.Mock(side_effect=raise_exception))
        # call of 'init_host' method
        self.assertRaises(
            exception.ManilaException,
            self.share_manager.init_host,
        )

        # verification of call
        self.share_manager.db.backend_info_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), self.share_manager.host)
        self.share_manager.driver.get_backend_info.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        mock_ensure_share.assert_not_called()
        mock_ensure_shares.assert_not_called()

    def test_init_host_with_exception_on_update_access_rules(self):
        def raise_exception(*args, **kwargs):
            raise exception.ManilaException(message="Fake raise")

        instances, rules = self._setup_init_mocks()
        share_server = fakes.fake_share_server_get()
        fake_update_instances = {
            instances[0]['id']: {'status': 'available'},
            instances[2]['id']: {'status': 'available'},
            instances[4]['id']: {'status': 'available'}
        }
        smanager = self.share_manager
        self.mock_object(smanager.db, 'share_instances_get_all_by_host',
                         mock.Mock(return_value=instances))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instances[0], instances[2],
                                                instances[4]]))
        self.mock_object(self.share_manager.driver, 'ensure_share',
                         mock.Mock(return_value=None))
        self.mock_object(self.share_manager.driver, 'ensure_shares',
                         mock.Mock(return_value=fake_update_instances))
        self.mock_object(smanager, '_ensure_share_instance_has_pool')
        self.mock_object(smanager, '_get_share_server',
                         mock.Mock(return_value=share_server))
        self.mock_object(smanager, 'publish_service_capabilities')
        self.mock_object(manager.LOG, 'exception')
        self.mock_object(manager.LOG, 'info')
        self.mock_object(smanager.access_helper,
                         'reset_rules_to_queueing_states')
        self.mock_object(smanager.access_helper, 'update_access_rules',
                         mock.Mock(side_effect=raise_exception))
        self.mock_object(smanager, '_get_share_server_dict',
                         mock.Mock(return_value=share_server))

        dict_instances = [self._get_share_instance_dict(
            instance, share_server=share_server) for instance in instances]

        # call of 'init_host' method
        smanager.init_host()

        # verification of call
        (smanager.db.share_instances_get_all_by_host.
            assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    smanager.host))
        smanager.driver.do_setup.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        smanager.driver.check_for_setup_error.assert_called_with()
        smanager._ensure_share_instance_has_pool.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext), instances[0]),
            mock.call(utils.IsAMatcher(context.RequestContext), instances[2]),
        ])
        smanager.driver.ensure_shares.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            [dict_instances[0], dict_instances[2], dict_instances[4]])
        (self.share_manager.publish_service_capabilities.
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext)))
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
        manager.LOG.exception.assert_has_calls([
            mock.call(mock.ANY, mock.ANY),
        ])

    def test_create_share_instance_from_snapshot_with_server(self):
        """Test share can be created from snapshot if server exists."""
        network = db_utils.create_share_network()
        subnet = db_utils.create_share_network_subnet(
            share_network_id=network['id'])
        server = db_utils.create_share_server(
            share_network_subnets=[subnet], host='fake_host',
            backend_details=dict(fake='fake'))
        parent_share = db_utils.create_share(share_network_id='net-id',
                                             share_server_id=server['id'])
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
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
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
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

    def test_create_share_instance_from_snapshot_status_creating(self):
        """Test share can be created from snapshot in asynchronous mode."""
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']
        create_from_snap_ret = {
            'status': constants.STATUS_CREATING_FROM_SNAPSHOT,
        }
        driver_call = self.mock_object(
            self.share_manager.driver, 'create_share_from_snapshot',
            mock.Mock(return_value=create_from_snap_ret))
        self.share_manager.create_share_instance(
            self.context, share.instance['id'], snapshot_id=snapshot_id)
        self.assertTrue(driver_call.called)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertTrue(driver_call.called)
        self.assertEqual(constants.STATUS_CREATING_FROM_SNAPSHOT,
                         shr['status'])
        self.assertEqual(0, len(shr['export_locations']))

    def test_create_share_instance_from_snapshot_invalid_status(self):
        """Test share can't be created from snapshot with 'creating' status."""
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']
        create_from_snap_ret = {
            'status': constants.STATUS_CREATING,
        }
        driver_call = self.mock_object(
            self.share_manager.driver, 'create_share_from_snapshot',
            mock.Mock(return_value=create_from_snap_ret))

        self.assertRaises(exception.InvalidShareInstance,
                          self.share_manager.create_share_instance,
                          self.context,
                          share.instance['id'],
                          snapshot_id=snapshot_id)
        self.assertTrue(driver_call.called)
        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_ERROR, shr['status'])

    def test_create_share_instance_from_snapshot_export_locations_only(self):
        """Test share can be created from snapshot on old driver interface."""
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']
        create_from_snap_ret = ['/path/fake', '/path/fake2', '/path/fake3']

        driver_call = self.mock_object(
            self.share_manager.driver, 'create_share_from_snapshot',
            mock.Mock(return_value=create_from_snap_ret))
        self.share_manager.create_share_instance(
            self.context, share.instance['id'], snapshot_id=snapshot_id)
        self.assertTrue(driver_call.called)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_AVAILABLE, shr['status'])
        self.assertEqual(3, len(shr['export_locations']))

    def test_create_share_instance_from_snapshot(self):
        """Test share can be created from snapshot."""
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
        share_id = share['id']
        snapshot = db_utils.create_snapshot(share_id=share_id)
        snapshot_id = snapshot['id']

        self.share_manager.create_share_instance(
            self.context, share.instance['id'], snapshot_id=snapshot_id)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_AVAILABLE, shr['status'])
        self.assertGreater(len(shr['export_location']), 0)
        self.assertEqual(2, len(shr['export_locations']))

    def test_create_share_instance_for_share_with_replication_support(self):
        """Test update call is made to update replica_state."""
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(replication_type='writable',
                                      share_type_id=share_type['id'])
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
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            replica['project_id'],
            resource_type=message_field.Resource.SHARE_REPLICA,
            resource_id=replica['id'],
            detail=message_field.Detail.NO_ACTIVE_REPLICA)

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
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            replica['project_id'],
            resource_type=message_field.Resource.SHARE_REPLICA,
            resource_id=replica['id'],
            detail=message_field.Detail.UNEXPECTED_NETWORK)

    def test_create_share_replica_with_share_server_exception(self):
        replica = fake_replica()
        share_network_subnet = db_utils.create_share_network_subnet(
            share_network_id=replica['share_network_id'],
            availability_zone_id=replica['availability_zone_id'])
        manager.CONF.set_default('driver_handles_share_servers', True)
        self.mock_object(db, 'share_instance_access_copy',
                         mock.Mock(return_value=[]))
        self.mock_object(db, 'share_replicas_get_available_active_replica',
                         mock.Mock(return_value=fake_replica(id='fake2')))
        self.mock_object(db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(
            db, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=[share_network_subnet]))
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
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            replica['project_id'],
            resource_type=message_field.Resource.SHARE_REPLICA,
            resource_id=replica['id'],
            detail=message_field.Detail.NO_SHARE_SERVER)

    def test_create_share_replica_driver_error_on_creation(self):
        fake_access_rules = [{'id': '1'}, {'id': '2'}, {'id': '3'}]
        replica = fake_replica()
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
            self.share_manager.access_helper,
            'get_and_update_share_instance_access_rules_status')
        self.mock_object(self.share_manager, '_get_share_server')

        driver_call = self.mock_object(
            self.share_manager.driver, 'create_replica',
            mock.Mock(side_effect=exception.ManilaException))

        self.assertRaises(exception.ManilaException,
                          self.share_manager.create_share_replica,
                          self.context, replica)
        mock_replica_update_call.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), replica['id'],
            {'status': constants.STATUS_ERROR,
             'replica_state': constants.STATUS_ERROR})
        mock_share_replica_access_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_instance_id=replica['id'],
            status=constants.SHARE_INSTANCE_RULES_ERROR)
        self.assertFalse(mock_export_locs_update_call.called)
        self.assertTrue(mock_log_error.called)
        self.assertFalse(mock_log_info.called)
        self.assertTrue(driver_call.called)
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            replica['project_id'],
            resource_type=message_field.Resource.SHARE_REPLICA,
            resource_id=replica['id'],
            exception=mock.ANY)

    def test_create_share_replica_invalid_locations_state(self):
        driver_retval = {
            'export_locations': 'FAKE_EXPORT_LOC',
        }
        replica = fake_replica(share_network='',
                               access_rules_status=constants.STATUS_ACTIVE)
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
            self.share_manager.access_helper,
            'get_and_update_share_instance_access_rules_status')

        self.share_manager.create_share_replica(self.context, replica)

        self.assertFalse(mock_replica_update_call.called)
        mock_share_replica_access_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_instance_id=replica['id'], status=constants.STATUS_ACTIVE)
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
            replica_state=constants.REPLICA_STATE_OUT_OF_SYNC,
            access_rules_status=None)
        replica_2 = fake_replica(id='fake2')
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, replica_2]))
        self.share_manager.availability_zone = 'fake_az'
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
                       'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC,
                       'progress': '100%'}),
        ]
        mock_export_locs_update_call = self.mock_object(
            db, 'share_export_locations_update')
        mock_log_info = self.mock_object(manager.LOG, 'info')
        mock_log_warning = self.mock_object(manager.LOG, 'warning')
        mock_log_error = self.mock_object(manager.LOG, 'warning')
        self.mock_object(db, 'share_instance_access_get',
                         mock.Mock(return_value=fake_access_rules[0]))
        mock_share_replica_access_rule_update = self.mock_object(
            self.share_manager.access_helper,
            'get_and_update_share_instance_access_rules')
        mock_share_replica_access_state_update = self.mock_object(
            self.share_manager,
            '_update_share_instance_access_rules_state')
        driver_call = self.mock_object(
            self.share_manager.driver, 'create_replica',
            mock.Mock(return_value=replica))
        self.mock_object(self.share_manager, '_get_share_server', mock.Mock())

        self.share_manager.create_share_replica(self.context, replica)

        mock_replica_update_call.assert_has_calls(mock_calls, any_order=False)
        mock_share_replica_access_rule_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_instance_id=replica['id'],
            conditionally_change={'queued_to_apply': 'active'})
        mock_share_replica_access_state_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            replica['id'], constants.STATUS_ACTIVE)
        self.assertTrue(mock_export_locs_update_call.called)
        self.assertTrue(mock_log_info.called)
        self.assertFalse(mock_log_warning.called)
        self.assertFalse(mock_log_error.called)
        self.assertTrue(driver_call.called)

    @ddt.data(True, False)
    def test_create_share_replica(self, has_snapshots):
        replica = fake_replica(
            share_network='',
            replica_state=constants.REPLICA_STATE_IN_SYNC,
            access_rules_status='active')
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
        mock_share_replica_access_rule_update = self.mock_object(
            self.share_manager.access_helper,
            'get_and_update_share_instance_access_rules')
        mock_share_replica_access_state_update = self.mock_object(
            self.share_manager,
            '_update_share_instance_access_rules_state')

        driver_call = self.mock_object(
            self.share_manager.driver, 'create_replica',
            mock.Mock(return_value=replica))
        self.mock_object(self.share_manager, '_get_share_server')

        self.share_manager.create_share_replica(self.context, replica)

        mock_replica_update_call.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), replica['id'],
            {'status': constants.STATUS_AVAILABLE,
             'replica_state': constants.REPLICA_STATE_IN_SYNC,
             'progress': '100%'})
        mock_share_replica_access_rule_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_instance_id=replica['id'],
            conditionally_change={'queued_to_apply': 'active'})
        mock_share_replica_access_state_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            replica['id'], constants.STATUS_ACTIVE)
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
                self.assertIn('active_replica_snapshot', snapshot_dict)
                self.assertIn('share_replica_snapshot', snapshot_dict)
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
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.DELETE_ACCESS_RULES,
            replica['project_id'],
            resource_type=message_field.Resource.SHARE_REPLICA,
            resource_id=replica['id'],
            exception=mock.ANY)

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
            for r in (replica, active_replica)]

        self.assertRaises(exception.ManilaException,
                          self.share_manager.promote_share_replica,
                          self.context, replica)
        mock_replica_update.assert_has_calls(expected_update_calls)
        self.assertFalse(mock_info_log.called)

        expected_message_calls = [
            mock.call(
                utils.IsAMatcher(context.RequestContext),
                message_field.Action.PROMOTE,
                r['project_id'],
                resource_type=message_field.Resource.SHARE_REPLICA,
                resource_id=r['id'],
                exception=mock.ANY)
            for r in (replica, active_replica)]
        self.share_manager.message_api.create.assert_has_calls(
            expected_message_calls)

    @ddt.data([], None)
    def test_promote_share_replica_driver_update_nothing_has_snaps(self,
                                                                   retval):
        replica = fake_replica(
            replication_type=constants.REPLICATION_TYPE_READABLE)
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
                            'replica_state': constants.REPLICA_STATE_ACTIVE,
                            'cast_rules_to_readonly': False})
        call_2 = mock.call(
            mock.ANY, 'current_active_replica',
            {'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC,
             'cast_rules_to_readonly': True})
        expected_update_calls = [call_1, call_2]

        self.share_manager.promote_share_replica(self.context, replica)

        self.assertFalse(mock_export_locs_update.called)
        mock_replica_update.assert_has_calls(expected_update_calls,
                                             any_order=True)
        mock_snap_instance_update.assert_called_once_with(
            mock.ANY, 'test_creating_to_err',
            {'status': constants.STATUS_ERROR})
        self.assertEqual(2, mock_info_log.call_count)

    @ddt.data(constants.REPLICATION_TYPE_READABLE,
              constants.REPLICATION_TYPE_WRITABLE,
              constants.REPLICATION_TYPE_DR)
    def test_promote_share_replica_driver_updates_replica_list(self, rtype):
        replica = fake_replica(replication_type=rtype)
        active_replica = fake_replica(
            id='current_active_replica',
            replica_state=constants.REPLICA_STATE_ACTIVE)
        replica_list = [
            replica, active_replica, fake_replica(id=3),
            fake_replica(id='one_more_replica'),
        ]
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
                'export_locations': ['TEST3', 'TEST4'],
            },
            {
                'id': replica_list[3]['id'],
                'export_locations': ['TEST5', 'TEST6'],
                'replica_state': constants.REPLICA_STATE_IN_SYNC,
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
        reset_replication_change_updates = {
            'replica_state': constants.STATUS_ACTIVE,
            'status': constants.STATUS_AVAILABLE,
            'cast_rules_to_readonly': False,
        }
        demoted_replica_updates = {
            'replica_state': constants.REPLICA_STATE_IN_SYNC,
            'cast_rules_to_readonly': False,
        }
        if rtype == constants.REPLICATION_TYPE_READABLE:
            demoted_replica_updates['cast_rules_to_readonly'] = True
        reset_replication_change_call = mock.call(
            mock.ANY, replica['id'], reset_replication_change_updates)
        demoted_replica_update_call = mock.call(
            mock.ANY, active_replica['id'], demoted_replica_updates
        )
        additional_replica_update_call = mock.call(
            mock.ANY, replica_list[3]['id'], {
                'replica_state': constants.REPLICA_STATE_IN_SYNC,
            }
        )

        self.share_manager.promote_share_replica(self.context, replica)

        self.assertEqual(3, mock_export_locs_update.call_count)
        mock_replica_update.assert_has_calls([
            demoted_replica_update_call,
            additional_replica_update_call,
            reset_replication_change_call,
        ])
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
                         mock.Mock(return_value=fakes.fake_share_server_get()))
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
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.UPDATE,
            replica['project_id'],
            resource_type=message_field.Resource.SHARE_REPLICA,
            resource_id=replica['id'],
            exception=mock.ANY)

    def test__share_replica_update_driver_exception_ignored(self):
        mock_debug_log = self.mock_object(manager.LOG, 'debug')
        replica = fake_replica(replica_state=constants.STATUS_ERROR)
        active_replica = fake_replica(replica_state=constants.STATUS_ACTIVE)
        self.mock_object(db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=[replica, active_replica]))
        self.mock_object(self.share_manager.db, 'share_replica_get',
                         mock.Mock(return_value=replica))
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value={}))
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
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.UPDATE,
            replica['project_id'],
            resource_type=message_field.Resource.SHARE_REPLICA,
            resource_id=replica['id'],
            exception=mock.ANY)

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
                               share_server=fakes.fake_share_server_get())
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
                         mock.Mock(return_value=fakes.fake_share_server_get()))
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
        # pylint: disable=unsubscriptable-object
        snapshot_list_arg = mock_driver_call.call_args[0][4]
        # pylint: enable=unsubscriptable-object
        self.assertIn('active_replica_snapshot', snapshot_list_arg[0])
        self.assertIn('share_replica_snapshot', snapshot_list_arg[0])
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

    def _get_snapshot_instance_dict(self, snapshot_instance, share,
                                    snapshot=None):
        expected_snapshot_instance_dict = {
            'status': constants.STATUS_CREATING,
            'share_id': share['id'],
            'share_name': snapshot_instance['share_name'],
            'deleted': snapshot_instance['deleted'],
            'share': share,
            'updated_at': snapshot_instance['updated_at'],
            'snapshot_id': snapshot_instance['snapshot_id'],
            'id': snapshot_instance['id'],
            'name': snapshot_instance['name'],
            'created_at': snapshot_instance['created_at'],
            'share_instance_id': snapshot_instance['share_instance_id'],
            'progress': snapshot_instance['progress'],
            'deleted_at': snapshot_instance['deleted_at'],
            'provider_location': snapshot_instance['provider_location'],
        }
        if snapshot:
            expected_snapshot_instance_dict.update({
                'size': snapshot['size'],
            })
        return expected_snapshot_instance_dict

    def test_create_snapshot_driver_exception(self):

        def _raise_not_found(self, *args, **kwargs):
            raise exception.NotFound()

        share_id = 'FAKE_SHARE_ID'
        share = fakes.fake_share(id=share_id, instance={'id': 'fake_id'})
        snapshot_instance = fakes.fake_snapshot_instance(
            share_id=share_id, share=share, name='fake_snapshot')
        snapshot = fakes.fake_snapshot(
            share_id=share_id, share=share, instance=snapshot_instance,
            project_id=self.context.project_id)
        snapshot_id = snapshot['id']
        self.mock_object(self.share_manager.driver, "create_snapshot",
                         mock.Mock(side_effect=_raise_not_found))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        self.mock_object(self.share_manager.db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(self.share_manager.db, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))
        db_update = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')
        expected_snapshot_instance_dict = self._get_snapshot_instance_dict(
            snapshot_instance, share)

        self.assertRaises(exception.NotFound,
                          self.share_manager.create_snapshot,
                          self.context, share_id, snapshot_id)
        db_update.assert_called_once_with(self.context,
                                          snapshot_instance['id'],
                                          {'status': constants.STATUS_ERROR})

        self.share_manager.driver.create_snapshot.assert_called_once_with(
            self.context, expected_snapshot_instance_dict, share_server=None)
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            snapshot['project_id'],
            resource_type=message_field.Resource.SHARE_SNAPSHOT,
            resource_id=snapshot_instance['id'],
            exception=mock.ANY)

    @ddt.data({'model_update': {}, 'mount_snapshot_support': True},
              {'model_update': {}, 'mount_snapshot_support': False},
              {'model_update': {'export_locations': [
                  {'path': '/path1', 'is_admin_only': True},
                  {'path': '/path2', 'is_admin_only': False}
              ]}, 'mount_snapshot_support': True},
              {'model_update': {'export_locations': [
                  {'path': '/path1', 'is_admin_only': True},
                  {'path': '/path2', 'is_admin_only': False}
              ]}, 'mount_snapshot_support': False})
    @ddt.unpack
    def test_create_snapshot(self, model_update, mount_snapshot_support):
        export_locations = model_update.get('export_locations')
        share_id = 'FAKE_SHARE_ID'
        share = fakes.fake_share(
            id=share_id,
            instance={'id': 'fake_id'},
            mount_snapshot_support=mount_snapshot_support)
        snapshot_instance = fakes.fake_snapshot_instance(
            share_id=share_id, share=share, name='fake_snapshot')
        snapshot = fakes.fake_snapshot(
            share_id=share_id, share=share, instance=snapshot_instance)
        snapshot_id = snapshot['id']
        self.mock_object(self.share_manager.db, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager.db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        mock_export_update = self.mock_object(
            self.share_manager.db,
            'share_snapshot_instance_export_location_create')
        expected_update_calls = [
            mock.call(self.context, snapshot_instance['id'],
                      {'status': constants.STATUS_AVAILABLE,
                       'progress': '100%'})
        ]

        expected_snapshot_instance_dict = self._get_snapshot_instance_dict(
            snapshot_instance, share)

        self.mock_object(
            self.share_manager.driver, 'create_snapshot',
            mock.Mock(return_value=model_update))
        db_update = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')

        return_value = self.share_manager.create_snapshot(
            self.context, share_id, snapshot_id)

        self.assertIsNone(return_value)
        self.share_manager.driver.create_snapshot.assert_called_once_with(
            self.context, expected_snapshot_instance_dict, share_server=None)
        db_update.assert_has_calls(expected_update_calls, any_order=True)
        if mount_snapshot_support and export_locations:
            snap_ins_id = snapshot.instance['id']
            for i in range(0, 2):
                export_locations[i]['share_snapshot_instance_id'] = snap_ins_id
            mock_export_update.assert_has_calls([
                mock.call(utils.IsAMatcher(context.RequestContext),
                          export_locations[0]),
                mock.call(utils.IsAMatcher(context.RequestContext),
                          export_locations[1]),
            ])
        else:
            mock_export_update.assert_not_called()

    @ddt.data(exception.ShareSnapshotIsBusy(snapshot_name='fake_name'),
              exception.NotFound())
    def test_delete_snapshot_driver_exception(self, exc):

        share_id = 'FAKE_SHARE_ID'
        share = fakes.fake_share(id=share_id, instance={'id': 'fake_id'},
                                 mount_snapshot_support=True)
        snapshot_instance = fakes.fake_snapshot_instance(
            share_id=share_id, share=share, name='fake_snapshot')
        snapshot = fakes.fake_snapshot(
            share_id=share_id, share=share, instance=snapshot_instance,
            project_id=self.context.project_id)
        snapshot_id = snapshot['id']

        update_access = self.mock_object(
            self.share_manager.snapshot_access_helper, 'update_access_rules')
        self.mock_object(self.share_manager.driver, "delete_snapshot",
                         mock.Mock(side_effect=exc))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        self.mock_object(self.share_manager.db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(self.share_manager.db, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))
        self.mock_object(
            self.share_manager.db, 'share_get', mock.Mock(return_value=share))
        db_update = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')
        db_destroy_call = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_delete')
        expected_snapshot_instance_dict = self._get_snapshot_instance_dict(
            snapshot_instance, share)
        mock_exception_log = self.mock_object(manager.LOG, 'exception')
        self.assertRaises(type(exc), self.share_manager.delete_snapshot,
                          self.context, snapshot_id)
        db_update.assert_called_once_with(
            mock.ANY, snapshot_instance['id'],
            {'status': constants.STATUS_ERROR_DELETING})
        self.share_manager.driver.delete_snapshot.assert_called_once_with(
            mock.ANY, expected_snapshot_instance_dict,
            share_server=None)
        update_access.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            snapshot_instance['id'], delete_all_rules=True, share_server=None)
        self.assertFalse(db_destroy_call.called)
        self.assertFalse(mock_exception_log.called)
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.DELETE,
            snapshot['project_id'],
            resource_type=message_field.Resource.SHARE_SNAPSHOT,
            resource_id=snapshot_instance['id'],
            exception=mock.ANY)

    @ddt.data(True, False)
    def test_delete_snapshot_with_quota_error(self, quota_error):

        share_id = 'FAKE_SHARE_ID'
        share = fakes.fake_share(id=share_id)
        snapshot_instance = fakes.fake_snapshot_instance(
            share_id=share_id, share=share, name='fake_snapshot')
        snapshot = fakes.fake_snapshot(
            share_id=share_id, share=share, instance=snapshot_instance,
            project_id=self.context.project_id, size=1)
        snapshot_id = snapshot['id']
        self.mock_object(self.share_manager.db, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager.db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        mock_exception_log = self.mock_object(manager.LOG, 'exception')
        expected_exc_count = 1 if quota_error else 0

        expected_snapshot_instance_dict = self._get_snapshot_instance_dict(
            snapshot_instance, share)

        self.mock_object(self.share_manager.driver, 'delete_snapshot')
        db_update_call = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')
        snapshot_destroy_call = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_delete')
        side_effect = exception.QuotaError(code=500) if quota_error else None
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=side_effect))
        quota_commit_call = self.mock_object(quota.QUOTAS, 'commit')

        retval = self.share_manager.delete_snapshot(
            self.context, snapshot_id)

        self.assertIsNone(retval)
        self.share_manager.driver.delete_snapshot.assert_called_once_with(
            mock.ANY, expected_snapshot_instance_dict, share_server=None)
        self.assertFalse(db_update_call.called)
        self.assertTrue(snapshot_destroy_call.called)
        self.assertTrue(manager.QUOTAS.reserve.called)
        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY, project_id=self.context.project_id, snapshots=-1,
            snapshot_gigabytes=-snapshot['size'], user_id=snapshot['user_id'],
            share_type_id=share['instance']['share_type_id'])
        self.assertEqual(not quota_error, quota_commit_call.called)
        self.assertEqual(quota_error, mock_exception_log.called)
        self.assertEqual(expected_exc_count, mock_exception_log.call_count)

    @ddt.data(exception.ShareSnapshotIsBusy(snapshot_name='fake_snapshot'),
              exception.ManilaException)
    def test_delete_snapshot_ignore_exceptions_with_the_force(self, exc):

        def _raise_quota_error():
            raise exception.QuotaError(code='500')

        share_id = 'FAKE_SHARE_ID'
        share = fakes.fake_share(id=share_id)
        snapshot_instance = fakes.fake_snapshot_instance(
            share_id=share_id, share=share, name='fake_snapshot')
        snapshot = fakes.fake_snapshot(
            share_id=share_id, share=share, instance=snapshot_instance,
            project_id=self.context.project_id, size=1)
        snapshot_id = snapshot['id']
        self.mock_object(self.share_manager.db, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager.db, 'share_snapshot_instance_get',
                         mock.Mock(return_value=snapshot_instance))
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value=None))
        mock_exception_log = self.mock_object(manager.LOG, 'exception')
        self.mock_object(self.share_manager.driver, 'delete_snapshot',
                         mock.Mock(side_effect=exc))
        db_update_call = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')
        snapshot_destroy_call = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_delete')
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=_raise_quota_error))
        quota_commit_call = self.mock_object(quota.QUOTAS, 'commit')

        retval = self.share_manager.delete_snapshot(
            self.context, snapshot_id, force=True)

        self.assertIsNone(retval)
        self.assertEqual(2, mock_exception_log.call_count)
        snapshot_destroy_call.assert_called_once_with(
            mock.ANY, snapshot_instance['id'])
        self.assertFalse(quota_commit_call.called)
        self.assertFalse(db_update_call.called)
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.DELETE,
            snapshot['project_id'],
            resource_type=message_field.Resource.SHARE_SNAPSHOT,
            resource_id=snapshot_instance['id'],
            exception=mock.ANY)

    def test_create_share_instance_with_share_network_dhss_false(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=False))
        share_network_id = 'fake_sn'
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(
            share_network_id=share_network_id,
            share_type_id=share_type['id'])
        share_instance = share.instance
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
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            str(share.project_id),
            resource_type=message_field.Resource.SHARE,
            resource_id=share['id'],
            detail=mock.ANY)

    def test_create_share_instance_with_share_network_server_not_exists(self):
        """Test share can be created without share server."""

        share_net = db_utils.create_share_network()
        share_net_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_net['id'],
            availability_zone_id=None,
        )
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(
            share_network_id=share_net['id'],
            share_type_id=share_type['id'])
        share_id = share['id']

        def fake_setup_server(context, share_network, *args, **kwargs):
            return db_utils.create_share_server(
                share_network_subnet_id=share_net_subnet['id'],
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

    def test_create_share_instance_with_network_port_limit_exceeded(self):
        share_network = db_utils.create_share_network(id='fake_sn_id')
        share_net_subnet = db_utils.create_share_network_subnet(
            id='fake_sns_id', share_network_id=share_network['id']
        )
        share_type = db_utils.create_share_type()
        fake_share = db_utils.create_share(
            share_network_id=share_network['id'], size=1,
            share_type_id=share_type['id'])
        fake_metadata = {
            'request_host': 'fake_host',
            'share_type_id': 'fake_share_type_id',
        }
        fake_server = db_utils.create_share_server(
            id='fake_srv_id', status=constants.STATUS_CREATING,
            share_network_subnets=[share_net_subnet])

        self.mock_object(self.share_manager, '_build_server_metadata',
                         mock.Mock(return_value=fake_metadata))
        self.mock_object(db, 'share_server_create',
                         mock.Mock(return_value=fake_server))
        self.mock_object(db, 'share_instance_update',
                         mock.Mock(return_value=fake_share.instance))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=fake_share.instance))
        self.mock_object(
            db, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=[share_net_subnet]))
        self.mock_object(manager.LOG, 'error')

        def raise_manila_exception(*args, **kwargs):
            raise exception.PortLimitExceeded()

        self.mock_object(self.share_manager, '_setup_server',
                         mock.Mock(side_effect=raise_manila_exception))

        self.assertRaises(
            exception.PortLimitExceeded,
            self.share_manager.create_share_instance,
            self.context,
            fake_share.instance['id'],
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
            utils.IsAMatcher(context.RequestContext), fake_server,
            fake_metadata)
        manager.LOG.error.assert_called_with(mock.ANY,
                                             fake_share.instance['id'])
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            str(fake_share.project_id),
            resource_type=message_field.Resource.SHARE,
            resource_id=fake_share['id'],
            detail=(
                message_field.Detail.SHARE_NETWORK_PORT_QUOTA_LIMIT_EXCEEDED))

    def test_create_share_instance_with_share_network_server_fail(self):
        share_network = db_utils.create_share_network(id='fake_sn_id')
        share_net_subnet = db_utils.create_share_network_subnet(
            id='fake_sns_id', share_network_id=share_network['id']
        )
        share_type = db_utils.create_share_type()
        fake_share = db_utils.create_share(
            share_network_id=share_network['id'],
            share_type_id=share_type['id'],
            size=1
        )
        fake_metadata = {
            'request_host': 'fake_host',
            'share_type_id': 'fake_share_type_id',
        }
        fake_server = db_utils.create_share_server(
            id='fake_srv_id', status=constants.STATUS_CREATING,
            share_network_subnets=[share_net_subnet])

        self.mock_object(self.share_manager, '_build_server_metadata',
                         mock.Mock(return_value=fake_metadata))
        self.mock_object(db, 'share_server_create',
                         mock.Mock(return_value=fake_server))
        self.mock_object(db, 'share_instance_update',
                         mock.Mock(return_value=fake_share.instance))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=fake_share.instance))
        self.mock_object(
            db, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=[share_net_subnet]))
        self.mock_object(manager.LOG, 'error')

        def raise_share_server_not_found(*args, **kwargs):
            raise exception.ShareServerNotFound(
                share_server_id=fake_server['id'])

        def raise_manila_exception(*args, **kwargs):
            raise exception.ManilaException()

        self.mock_object(db,
                         'share_server_get_all_by_host_and_share_subnet_valid',
                         mock.Mock(side_effect=raise_share_server_not_found))
        self.mock_object(self.share_manager, '_setup_server',
                         mock.Mock(side_effect=raise_manila_exception))

        self.assertRaises(
            exception.ManilaException,
            self.share_manager.create_share_instance,
            self.context,
            fake_share.instance['id'],
        )
        (db.share_server_get_all_by_host_and_share_subnet_valid.
            assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                self.share_manager.host,
                share_net_subnet['id'],
            ))
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
            utils.IsAMatcher(context.RequestContext), fake_server,
            fake_metadata)
        manager.LOG.error.assert_called_with(mock.ANY,
                                             fake_share.instance['id'])
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            str(fake_share.project_id),
            resource_type=message_field.Resource.SHARE,
            resource_id=fake_share['id'],
            detail=message_field.Detail.NO_SHARE_SERVER)

    def test_create_share_instance_with_share_network_subnet_not_found(self):
        """Test creation fails if share network not found."""

        self.mock_object(manager.LOG, 'error')

        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_network_id='fake-net-id',
                                      share_type_id=share_type['id'])
        share_id = share['id']
        self.assertRaises(
            exception.ShareNetworkSubnetNotFound,
            self.share_manager.create_share_instance,
            self.context,
            share.instance['id']
        )
        manager.LOG.error.assert_called_with(mock.ANY, share.instance['id'])
        shr = db.share_get(self.context, share_id)
        self.assertEqual(constants.STATUS_ERROR, shr['status'])
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            str(shr.project_id),
            resource_type=message_field.Resource.SHARE,
            resource_id=shr['id'],
            detail=message_field.Detail.NO_SHARE_SERVER)

    def test_create_share_instance_with_security_service_missing(self):
        """Test creation fails if security service association is missing."""

        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = True
        self.share_manager.driver.\
            dhss_mandatory_security_service_association = {
                'fake_proto': ['fake_ss', 'fake_ss2', ]
            }
        ss_data = {
            'name': 'fake_name',
            'ou': 'fake_ou',
            'domain': 'fake_domain',
            'server': 'fake_server',
            'dns_ip': 'fake_dns_ip',
            'user': 'fake_user',
            'type': 'fake_ss',
            'password': 'fake_pass',
        }
        security_service = db_utils.create_security_service(**ss_data)
        share_net = db_utils.create_share_network()
        share_net_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_net['id'],
            availability_zone_id=None,
        )
        db.share_network_add_security_service(context.get_admin_context(),
                                              share_net['id'],
                                              security_service['id'])
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(
            share_network_id=share_net['id'],
            share_proto='fake_proto',
            share_type_id=share_type['id'],
        )
        db_utils.create_share_server(
            share_network_subnet_id=share_net_subnet['id'],
            host=self.share_manager.host,
            status=constants.STATUS_ERROR)
        fake_server = {
            'id': 'fake_srv_id',
            'status': constants.STATUS_CREATING,
        }
        fake_metadata = {
            'request_host': 'fake_host',
            'share_type_id': 'fake_share_type_id',
        }
        self.mock_object(self.share_manager, '_build_server_metadata',
                         mock.Mock(return_value=fake_metadata))
        self.mock_object(db, 'share_server_create',
                         mock.Mock(return_value=fake_server))
        self.mock_object(self.share_manager, '_setup_server',
                         mock.Mock(return_value=fake_server))
        self.assertRaises(
            exception.InvalidRequest,
            self.share_manager.create_share_instance,
            self.context,
            share.instance['id']
        )
        share = db.share_get(self.context, share['id'])
        self.assertEqual(constants.STATUS_ERROR, share['status'])
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            str(share.project_id),
            resource_type=message_field.Resource.SHARE,
            resource_id=share['id'],
            detail=message_field.Detail.MISSING_SECURITY_SERVICE)

    @ddt.data(
        (True, 1, 3, 10, 0),
        (False, 1, 100, 5, 0),
        (True, 1, 10, 3, 0),
        (False, 1, 10, 10, 3),
        (False, 1, -1, 100, 3),
        (False, 1, 10, -1, 3),
    )
    @ddt.unpack
    def test__check_share_server_backend_limits(
            self, with_share_instance, resource_size, max_shares,
            max_gigabytes, expected_share_servers_len):
        """Tests if servers aren't being reused when its limits are reached."""

        # Creates three share servers to have a list of available share servers
        share_servers = [db_utils.create_share_server() for i in range(3)]
        share = db_utils.create_share()

        # Creates some share instances using the resource size
        share_instances = [
            db_utils.create_share_instance(
                size=resource_size, share_id=share['id'])
            for i in range(3)]

        # Creates some snapshot instances to make sure they are being
        # accounted
        snapshot_instances = [
            db_utils.create_snapshot(
                size=resource_size, share_id=share['id'])['instance']
            for i in range(3)]

        kwargs = {}

        driver_mock = mock.Mock()

        # Sets the driver max shares per share server and max server size
        # configured value to be the one received in the test parameters
        driver_mock.max_shares_per_share_server = max_shares
        driver_mock.max_share_server_size = max_gigabytes
        self.share_manager.driver = driver_mock
        self.mock_object(
            db, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=share_instances))
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=snapshot_instances))

        # NOTE(carloss): If with_share_instance, simulates the behavior where
        # the provide_share_server method call was not related to a request to
        # create a share group, where a share instance is not provided, neither
        # accounted, since it's a brand new group. When a share instance is
        # specified, it must be accounted to check if the creation of that
        # share instance in the given share server is going to exceed the
        # configured limit.
        if with_share_instance:
            share_instance = db_utils.create_share_instance(
                size=resource_size, share_id=share['id'])
            kwargs['share_instance'] = share_instance

        available_share_servers = (
            self.share_manager._check_share_server_backend_limits(
                self.context, share_servers, **kwargs))

        self.assertEqual(
            expected_share_servers_len, len(available_share_servers))

    def test__check_share_server_backend_limits_migrating_share(self):
        """Tests if servers aren't being reused when its limits are reached."""

        share_servers = [db_utils.create_share_server()]
        share = db_utils.create_share(status=constants.STATUS_MIGRATING_TO)

        resource_size = 1
        driver_mock = mock.Mock()
        driver_mock.max_shares_per_share_server = 2
        driver_mock.max_share_server_size = 2

        share_instances = [
            db_utils.create_share_instance(
                size=resource_size, share_id=share['id'], status=status,
                share_server_id=share_servers[0]['id'])
            for status in [
                constants.STATUS_MIGRATING, constants.STATUS_MIGRATING_TO]]
        share_instance_ids = [
            share_instances[0]['id'], share_instances[1]['id']]

        kwargs = {}

        self.share_manager.driver = driver_mock
        self.mock_object(
            db, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=share_instances))
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=[]))
        self.mock_object(db, 'share_get', mock.Mock(return_value=share))
        self.mock_object(api.API, 'get_migrating_instances',
                         mock.Mock(return_value=share_instance_ids))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share_instances[0]))

        # NOTE(carloss): If with_share_instance, simulates the behavior where
        # the provide_share_server method call was not related to a request to
        # create a share group, where a share instance is not provided, neither
        # accounted, since it's a brand new group. When a share instance is
        # specified, it must be accounted to check if the creation of that
        # share instance in the given share server is going to exceed the
        # configured limit.
        kwargs['share_instance'] = share_instances[1]

        available_share_servers = (
            self.share_manager._check_share_server_backend_limits(
                self.context, share_servers, **kwargs))

        self.assertEqual(
            1, len(available_share_servers))
        db.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, share_servers[0]['id'], with_share_data=True)
        (db.share_snapshot_instance_get_all_with_filters.
            assert_called_once_with(
                self.context, {"share_instance_ids": share_instance_ids},
                with_share_data=True))
        db.share_get.assert_called_once_with(self.context, share['id'])
        api.API.get_migrating_instances.assert_called_once_with(share)
        db.share_instance_get.assert_called_once_with(
            self.context, share_instances[0]['id'])

    def test__check_share_server_backend_limits_unlimited(self):
        driver_mock = mock.Mock()
        driver_mock.max_shares_per_share_server = -1
        driver_mock.max_share_server_size = -1
        self.share_manager.driver = driver_mock

        share_servers = [db_utils.create_share_server() for i in range(3)]

        available_share_servers = (
            self.share_manager._check_share_server_backend_limits(
                self.context, share_servers))

        self.assertEqual(share_servers, available_share_servers)

    def test_create_share_instance_with_share_network_server_exists(self):
        """Test share can be created with existing share server."""
        share_net = db_utils.create_share_network()
        share_net_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_net['id'],
            availability_zone_id=None,
        )
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_type_id=share_type['id'])
        share_srv = db_utils.create_share_server(
            share_network_subnets=[share_net_subnet],
            host=self.share_manager.host)

        share_id = share['id']

        self.mock_object(manager.LOG, 'info')
        driver_mock = mock.Mock()
        driver_mock.max_shares_per_share_server = -1
        driver_mock.max_share_server_size = -1
        driver_mock.create_share.return_value = "fake_location"
        driver_mock.choose_share_server_compatible_with_share.return_value = (
            share_srv
        )
        self.share_manager.driver = driver_mock
        self.share_manager.driver.\
            dhss_mandatory_security_service_association = {}
        self.share_manager.create_share_instance(self.context,
                                                 share.instance['id'])
        self.assertFalse(self.share_manager.driver.setup_network.called)
        self.assertEqual(share_id, db.share_get(context.get_admin_context(),
                         share_id).id)

        shr = db.share_get(self.context, share_id)
        self.assertEqual(shr['status'], constants.STATUS_AVAILABLE)
        self.assertEqual(shr['share_server_id'], share_srv['id'])
        self.assertGreater(len(shr['export_location']), 0)
        self.assertEqual(1, len(shr['export_locations']))
        manager.LOG.info.assert_called_with(mock.ANY, share.instance['id'])

    @ddt.data('export_location', 'export_locations')
    def test_create_share_instance_with_error_in_driver(self, details_key):
        """Test db updates if share creation fails in driver."""
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
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
        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.CREATE,
            str(share.project_id),
            resource_type=message_field.Resource.SHARE,
            resource_id=share['id'],
            exception=mock.ANY)

    def test_create_share_instance_with_server_created(self):
        """Test share can be created and share server is created."""
        share_net = db_utils.create_share_network()
        share_net_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_net['id'],
            availability_zone_id=None)
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_type_id=share_type['id'],
                                      availability_zone=None)
        db_utils.create_share_server(
            share_network_subnet_id=share_net_subnet['id'],
            host=self.share_manager.host,
            status=constants.STATUS_ERROR)
        share_id = share['id']
        fake_server = {
            'id': 'fake_srv_id',
            'status': constants.STATUS_CREATING,
        }
        fake_metadata = {
            'request_host': 'fake_host',
            'share_type_id': 'fake_share_type_id',
        }

        self.mock_object(self.share_manager, '_build_server_metadata',
                         mock.Mock(return_value=fake_metadata))
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
            utils.IsAMatcher(context.RequestContext), fake_server,
            fake_metadata)

    def test_create_share_instance_update_replica_state(self):
        share_net = db_utils.create_share_network()
        share_net_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_net['id'],
            availability_zone_id=None
        )
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_type_id=share_type['id'],
                                      replication_type='dr',
                                      availability_zone=None)
        db_utils.create_share_server(
            share_network_subnet_id=share_net_subnet['id'],
            host=self.share_manager.host, status=constants.STATUS_ERROR)
        share_id = share['id']
        fake_server = {
            'id': 'fake_srv_id',
            'status': constants.STATUS_CREATING,
        }
        fake_metadata = {
            'request_host': 'fake_host',
            'share_type_id': 'fake_share_type_id',
        }
        self.mock_object(self.share_manager, '_build_server_metadata',
                         mock.Mock(return_value=fake_metadata))
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
            utils.IsAMatcher(context.RequestContext), fake_server,
            fake_metadata)

    @mock.patch('manila.tests.fake_notifier.FakeNotifier._notify')
    def test_create_delete_share_instance(self, mock_notify):
        """Test share can be created and deleted."""
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])

        mock_notify.assert_not_called()

        self.share_manager.create_share_instance(
            self.context, share.instance['id'])

        self.assert_notify_called(mock_notify,
                                  (['INFO', 'share.create.start'],
                                   ['INFO', 'share.create.end']))

        self.share_manager.delete_share_instance(
            self.context, share.instance['id'])

        self.assert_notify_called(mock_notify,
                                  (['INFO', 'share.create.start'],
                                   ['INFO', 'share.create.end'],
                                   ['INFO', 'share.delete.start'],
                                   ['INFO', 'share.delete.end']))

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

        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
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
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(availability_zone=None,
                                      share_type_id=share_type['id'])
        share_id = share['id']

        self.share_manager.create_share_instance(
            self.context, share.instance['id'])

        actual_share = db.share_get(context.get_admin_context(), share_id)
        self.assertIsNotNone(actual_share.availability_zone)
        self.assertEqual(manager.CONF.storage_availability_zone,
                         actual_share.availability_zone)

    def test_provide_share_server_for_share_incompatible_servers(self):
        fake_exception = exception.ManilaException("fake")
        fake_share_network = db_utils.create_share_network(id='fake_sn_id')
        fake_share_net_subnets = [db_utils.create_share_network_subnet(
            id='fake_sns_id', share_network_id=fake_share_network['id']
        )]
        fake_share_server = db_utils.create_share_server(id='fake')
        share = db_utils.create_share()

        db_method_mock = self.mock_object(
            db, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=fake_share_net_subnets))
        self.mock_object(db,
                         'share_server_get_all_by_host_and_share_subnet_valid',
                         mock.Mock(return_value=[fake_share_server]))
        self.mock_object(
            self.share_manager, '_check_share_server_backend_limits',
            mock.Mock(return_value=[fake_share_server]))
        self.mock_object(
            self.share_manager.driver,
            "choose_share_server_compatible_with_share",
            mock.Mock(side_effect=fake_exception)
        )

        self.assertRaises(exception.ManilaException,
                          self.share_manager._provide_share_server_for_share,
                          self.context, fake_share_network['id'],
                          share.instance)

        db_method_mock.assert_called_once_with(
            self.context, fake_share_network['id'],
            availability_zone_id=share.instance.get('availability_zone_id')
        )
        driver_mock = self.share_manager.driver
        driver_method_mock = (
            driver_mock.choose_share_server_compatible_with_share
        )
        driver_method_mock.assert_called_once_with(
            self.context, [fake_share_server], share.instance,
            snapshot=None, share_group=None)

    def test_provide_share_server_for_share_invalid_arguments(self):
        self.assertRaises(ValueError,
                          self.share_manager._provide_share_server_for_share,
                          self.context, None, None)

    def test_provide_share_server_for_share_parent_ss_not_found(self):
        fake_parent_id = "fake_server_id"
        fake_share_network = db_utils.create_share_network(id='fake_sn_id')
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
                          self.context, fake_share_network['id'],
                          share.instance, snapshot=fake_snapshot)

        db.share_server_get.assert_called_once_with(
            self.context, fake_parent_id)

    def test_provide_share_server_for_share_parent_ss_invalid(self):
        fake_parent_id = "fake_server_id"
        fake_share_network = db_utils.create_share_network(id='fake_sn_id')
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
                          self.context, fake_share_network['id'],
                          share.instance, snapshot=fake_snapshot)

        db.share_server_get.assert_called_once_with(
            self.context, fake_parent_id)

    def test_provide_share_server_for_share_group_incompatible_servers(self):
        fake_exception = exception.ManilaException("fake")
        sg = db_utils.create_share_group()
        share_network = {'id': 'fake_sn_id'}
        share_net_subnets = [{'id': 'fake_sns_id',
                             'share_network_id': share_network['id']}]
        fake_share_server = {
            'id': 'fake_id',
            'share_network_subnets': share_net_subnets,
        }
        self.mock_object(db,
                         'share_server_get_all_by_host_and_share_subnet_valid',
                         mock.Mock(return_value=[fake_share_server]))
        self.mock_object(
            self.share_manager.driver,
            "choose_share_server_compatible_with_share_group",
            mock.Mock(side_effect=fake_exception)
        )

        self.assertRaises(
            exception.ManilaException,
            self.share_manager._provide_share_server_for_share_group,
            self.context, "fake_sn_id", share_net_subnets, sg)

        driver_mock = self.share_manager.driver
        driver_method_mock = (
            driver_mock.choose_share_server_compatible_with_share_group)
        driver_method_mock.assert_called_once_with(
            self.context, [fake_share_server], sg, share_group_snapshot=None)

    def test_provide_share_server_for_share_group_invalid_arguments(self):
        self.assertRaises(
            exception.InvalidInput,
            self.share_manager._provide_share_server_for_share_group,
            self.context, None, None, None)

    def test_manage_share_driver_exception(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        CustomException = type('CustomException', (Exception,), dict())
        self.mock_object(self.share_manager.driver,
                         'manage_existing',
                         mock.Mock(side_effect=CustomException))
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))
        self.mock_object(
            self.share_manager, '_get_extra_specs_from_share_type',
            mock.Mock(return_value={}))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        self.mock_object(share_types, 'get_share_type', mock.Mock())
        self.mock_object(share_types, 'provision_filter_on_size', mock.Mock())
        share = db_utils.create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.assertRaises(
            CustomException,
            self.share_manager.manage_share,
            self.context, share_id, driver_options)

        (self.share_manager.driver.manage_existing.
            assert_called_once_with(mock.ANY, driver_options))

        self.share_manager.db.share_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id,
            {'status': constants.STATUS_MANAGE_ERROR, 'size': 0})
        (self.share_manager._get_extra_specs_from_share_type.
            assert_called_once_with(
                mock.ANY, share['instance']['share_type_id']))

    def _setup_provide_server_for_migration_test(self):
        source_share_server = db_utils.create_share_server()
        fake_share_network = db_utils.create_share_network()
        fake_network_subnet = db_utils.create_share_network_subnet(
            share_network_id=fake_share_network['id'])
        fake_dest_host = 'fakehost@fakebackend'
        fake_az = {
            'availability_zone_id': 'fake_az_id',
            'availability_zone_name': 'fake_az_name'
        }
        fake_data = {
            'source_share_server': source_share_server,
            'fake_share_network': fake_share_network,
            'fake_network_subnet': fake_network_subnet,
            'fake_dest_host': fake_dest_host,
            'fake_az': fake_az,
        }
        return fake_data

    def test__provide_share_server_for_migration_subnet_not_found(self):
        fake_data = self._setup_provide_server_for_migration_test()

        mock_subnet_get = self.mock_object(
            db, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=None))
        self.assertRaises(
            exception.ShareNetworkSubnetNotFound,
            self.share_manager._provide_share_server_for_migration,
            self.context,
            fake_data['source_share_server'],
            fake_data['fake_share_network']['id'],
            fake_data['fake_az']['availability_zone_id'],
            fake_data['fake_dest_host']
        )
        mock_subnet_get.assert_called_once_with(
            self.context, fake_data['fake_share_network']['id'],
            availability_zone_id=fake_data['fake_az']['availability_zone_id'])

    def test__provide_share_server_for_migration(self):
        fake_data = self._setup_provide_server_for_migration_test()
        dest_share_server = db_utils.create_share_server(
            share_network_subnets=[fake_data['fake_network_subnet']])
        expected_share_server_data = {
            'host': self.share_manager.host,
            'share_network_subnets': [fake_data['fake_network_subnet']],
            'status': constants.STATUS_CREATING,
            'security_service_update_support': False,
            'network_allocation_update_support': False,
        }
        fake_metadata = {
            'migration_destination': True,
            'request_host': fake_data['fake_dest_host'],
            'source_share_server': fake_data['source_share_server']
        }

        mock_subnet_get = self.mock_object(
            db, 'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=[fake_data['fake_network_subnet']]))
        mock_server_create = self.mock_object(
            db, 'share_server_create',
            mock.Mock(return_value=dest_share_server))
        mock_create_server_in_backend = self.mock_object(
            self.share_manager, '_create_share_server_in_backend',
            mock.Mock(return_value=dest_share_server))

        result = self.share_manager._provide_share_server_for_migration(
            self.context,
            fake_data['source_share_server'],
            fake_data['fake_share_network']['id'],
            fake_data['fake_az']['availability_zone_id'],
            fake_data['fake_dest_host']
        )
        self.assertEqual(result, dest_share_server)
        mock_subnet_get.assert_called_once_with(
            self.context, fake_data['fake_share_network']['id'],
            availability_zone_id=fake_data['fake_az']['availability_zone_id'])
        mock_server_create.assert_called_once_with(
            self.context, expected_share_server_data)
        mock_create_server_in_backend.assert_called_once_with(
            self.context, dest_share_server, metadata=fake_metadata)

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
        self.mock_object(share_types, 'get_share_type', mock.Mock())
        self.mock_object(share_types, 'provision_filter_on_size', mock.Mock())
        self.mock_object(
            self.share_manager, '_get_extra_specs_from_share_type',
            mock.Mock(return_value={}))
        share = db_utils.create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.assertRaises(
            exception.InvalidShare,
            self.share_manager.manage_share,
            self.context, share_id, driver_options)

        (self.share_manager.driver.manage_existing.
            assert_called_once_with(mock.ANY, driver_options))
        self.share_manager.db.share_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id,
            {'status': constants.STATUS_MANAGE_ERROR, 'size': 0})
        (self.share_manager._get_extra_specs_from_share_type.
            assert_called_once_with(
                mock.ANY, share['instance']['share_type_id']))

    def test_manage_share_quota_error(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value='False'))
        self.mock_object(self.share_manager.driver,
                         "manage_existing",
                         mock.Mock(return_value={'size': 3}))
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=exception.QuotaError))
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        self.mock_object(share_types, 'get_share_type', mock.Mock())
        self.mock_object(share_types, 'provision_filter_on_size', mock.Mock())
        self.mock_object(
            self.share_manager, '_get_extra_specs_from_share_type',
            mock.Mock(return_value={}))
        share = db_utils.create_share()
        share_id = share['id']
        driver_options = {'fake': 'fake'}

        self.assertRaises(
            exception.QuotaError,
            self.share_manager.manage_share,
            self.context, share_id, driver_options)

        (self.share_manager.driver.manage_existing.
            assert_called_once_with(mock.ANY, driver_options))
        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id,
            {'status': constants.STATUS_MANAGE_ERROR, 'size': 0})
        (self.share_manager._get_extra_specs_from_share_type.
            assert_called_once_with(
                mock.ANY, share['instance']['share_type_id']))

    def test_manage_share_incompatible_dhss(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        share = db_utils.create_share()
        self.mock_object(share_types, 'get_share_type', mock.Mock())
        self.mock_object(share_types, 'provision_filter_on_size', mock.Mock())
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value="True"))
        self.mock_object(
            self.share_manager, '_get_extra_specs_from_share_type',
            mock.Mock(return_value={}))
        self.assertRaises(
            exception.InvalidShare, self.share_manager.manage_share,
            self.context, share['id'], {})
        (self.share_manager._get_extra_specs_from_share_type.
            assert_called_once_with(
                mock.ANY, share['instance']['share_type_id']))

    @ddt.data({'dhss': True,
               'driver_data': {'size': 1, 'replication_type': None}},
              {'dhss': False,
               'driver_data': {'size': 2, 'name': 'fake',
                               'replication_type': 'dr'}},
              {'dhss': False,
               'driver_data': {'size': 3,
                               'export_locations': ['foo', 'bar', 'quuz'],
                               'replication_type': 'writable'}})
    @ddt.unpack
    def test_manage_share_valid_share(self, dhss, driver_data):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = dhss
        replication_type = driver_data.pop('replication_type')
        extra_specs = {}
        if replication_type is not None:
            extra_specs.update({'replication_type': replication_type})
        export_locations = driver_data.get('export_locations')
        self.mock_object(self.share_manager.db, 'share_update', mock.Mock())
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock())
        self.mock_object(share_types, 'get_share_type', mock.Mock())
        self.mock_object(share_types, 'provision_filter_on_size', mock.Mock())
        self.mock_object(
            self.share_manager.db,
            'share_export_locations_update',
            mock.Mock(side_effect=(
                self.share_manager.db.share_export_locations_update)))
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value=str(dhss)))
        self.mock_object(
            self.share_manager, '_get_extra_specs_from_share_type',
            mock.Mock(return_value=extra_specs))

        if dhss:
            mock_manage = self.mock_object(
                self.share_manager.driver,
                "manage_existing_with_server",
                mock.Mock(return_value=driver_data))
        else:
            mock_manage = self.mock_object(
                self.share_manager.driver,
                "manage_existing",
                mock.Mock(return_value=driver_data))
        share = db_utils.create_share(replication_type=replication_type)
        share_id = share['id']
        driver_options = {'fake': 'fake'}
        expected_deltas = {
            'project_id': share['project_id'],
            'user_id': self.context.user_id,
            'shares': 1,
            'gigabytes': driver_data['size'],
            'share_type_id': share['instance']['share_type_id'],
            'overquota_allowed': True
        }
        if replication_type:
            expected_deltas.update({'share_replicas': 1,
                                    'replica_gigabytes': driver_data['size']})

        self.share_manager.manage_share(self.context, share_id, driver_options)

        if dhss:
            mock_manage.assert_called_once_with(mock.ANY, driver_options, None)
        else:
            mock_manage.assert_called_once_with(mock.ANY, driver_options)
        if export_locations:
            (self.share_manager.db.share_export_locations_update.
                assert_called_once_with(
                    utils.IsAMatcher(context.RequestContext),
                    share.instance['id'], export_locations, delete=True))
        else:
            self.assertFalse(
                self.share_manager.db.share_export_locations_update.called)
        valid_share_data = {
            'status': constants.STATUS_AVAILABLE, 'launched_at': mock.ANY}
        if replication_type:
            valid_share_data['replica_state'] = constants.REPLICA_STATE_ACTIVE
        valid_share_data.update(driver_data)
        self.share_manager.db.share_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_id, valid_share_data)
        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY, **expected_deltas)
        (self.share_manager._get_extra_specs_from_share_type.
            assert_called_once_with(
                mock.ANY, share['instance']['share_type_id']))

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

    def _setup_unmanage_mocks(self, mock_driver=True, mock_unmanage=None,
                              dhss=False, supports_replication=False):
        if mock_driver:
            self.mock_object(self.share_manager, 'driver')
        replicas_list = []
        if supports_replication:
            replicas_list.append({'id': 'fake_id'})

        if mock_unmanage:
            if dhss:
                self.mock_object(
                    self.share_manager.driver, "unmanage_with_share_server",
                    mock_unmanage)
            else:
                self.mock_object(self.share_manager.driver, "unmanage",
                                 mock_unmanage)

        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager.db, 'share_instance_delete')
        self.mock_object(
            self.share_manager.db, 'share_replicas_get_all_by_share',
            mock.Mock(return_value=replicas_list))

    def test_unmanage_share_invalid_share(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        unmanage = mock.Mock(side_effect=exception.InvalidShare(reason="fake"))
        self._setup_unmanage_mocks(mock_driver=False, mock_unmanage=unmanage)
        share = db_utils.create_share()

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share['id'], {'status': constants.STATUS_UNMANAGE_ERROR})
        (self.share_manager.db.share_replicas_get_all_by_share.
            assert_called_once_with(mock.ANY, share['id']))

    @ddt.data(True, False)
    def test_unmanage_share_valid_share(self, supports_replication):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self._setup_unmanage_mocks(
            mock_driver=False, mock_unmanage=mock.Mock(),
            supports_replication=supports_replication)
        self.mock_object(quota.QUOTAS, 'reserve')
        share = db_utils.create_share()
        share_id = share['id']
        share_instance_id = share.instance['id']
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=share.instance))
        reservation_params = {
            'project_id': share['project_id'],
            'shares': -1,
            'gigabytes': -share['size'],
            'share_type_id': share['instance']['share_type_id'],
        }
        if supports_replication:
            reservation_params.update(
                {'share_replicas': -1, 'replica_gigabytes': -share['size']})

        self.share_manager.unmanage_share(self.context, share_id)

        (self.share_manager.driver.unmanage.
            assert_called_once_with(share.instance))
        self.share_manager.db.share_instance_delete.assert_called_once_with(
            mock.ANY, share_instance_id)
        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY, **reservation_params)
        (self.share_manager.db.share_replicas_get_all_by_share.
            assert_called_once_with(mock.ANY, share['id']))

    @ddt.data(True, False)
    def test_unmanage_share_valid_share_with_share_server(
            self, supports_replication):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = True
        self._setup_unmanage_mocks(
            mock_driver=False, mock_unmanage=mock.Mock(), dhss=True,
            supports_replication=supports_replication)
        server = db_utils.create_share_server(id='fake_server_id')
        share = db_utils.create_share(share_server_id='fake_server_id')
        self.mock_object(self.share_manager.db, 'share_server_update')
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=share.instance))
        self.mock_object(quota.QUOTAS, 'reserve')
        reservation_params = {
            'project_id': share['project_id'],
            'shares': -1,
            'gigabytes': -share['size'],
            'share_type_id': share['instance']['share_type_id'],
        }
        if supports_replication:
            reservation_params.update(
                {'share_replicas': -1, 'replica_gigabytes': -share['size']})

        share_id = share['id']
        share_instance_id = share.instance['id']

        self.share_manager.unmanage_share(self.context, share_id)

        (self.share_manager.driver.unmanage_with_server.
            assert_called_once_with(share.instance, server))
        self.share_manager.db.share_instance_delete.assert_called_once_with(
            mock.ANY, share_instance_id)
        self.share_manager.db.share_server_update.assert_called_once_with(
            mock.ANY, server['id'], {'is_auto_deletable': False})
        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY, **reservation_params)
        (self.share_manager.db.share_replicas_get_all_by_share
         .assert_called_once_with(mock.ANY, share['id']))

    def test_unmanage_share_valid_share_with_quota_error(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self._setup_unmanage_mocks(mock_driver=False,
                                   mock_unmanage=mock.Mock())
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=Exception()))
        share = db_utils.create_share()
        share_instance_id = share.instance['id']

        self.share_manager.unmanage_share(self.context, share['id'])

        self.share_manager.driver.unmanage.assert_called_once_with(mock.ANY)
        self.share_manager.db.share_instance_delete.assert_called_once_with(
            mock.ANY, share_instance_id)
        (self.share_manager.db.share_replicas_get_all_by_share.
            assert_called_once_with(mock.ANY, share['id']))

    def test_unmanage_share_remove_access_rules_error(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
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
        (self.share_manager.db.share_replicas_get_all_by_share.
            assert_called_once_with(mock.ANY, share['id']))

    def test_unmanage_share_valid_share_remove_access_rules(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
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
            mock.ANY, mock.ANY, delete_all_rules=True, share_server=None
        )
        smanager.db.share_instance_delete.assert_called_once_with(
            mock.ANY, share_instance_id)
        (self.share_manager.db.share_replicas_get_all_by_share.
            assert_called_once_with(mock.ANY, share['id']))

    def test_delete_share_instance_share_server_not_found(self):
        share_net = db_utils.create_share_network()
        share_network_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_net['id']
        )
        share = db_utils.create_share(
            share_network_id=share_net['id'],
            share_server_id='fake-id',
            share_network_subnets=[share_network_subnet])

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
        share_network_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_net['id']
        )
        sec_service = db_utils.create_security_service(
            share_network_id=share_net['id'])
        backend_details = dict(
            security_service_ldap=jsonutils.dumps(sec_service))
        if with_details:
            share_srv = db_utils.create_share_server(
                host=self.share_manager.host,
                backend_details=backend_details,
                share_network_subnets=[share_network_subnet])
        else:
            share_srv = db_utils.create_share_server(
                host=self.share_manager.host,
                share_network_subnets=[share_network_subnet])
            db.share_server_backend_details_set(
                context.get_admin_context(), share_srv['id'], backend_details)
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'],
                                      share_type_id=share_type['id'])
        mock_access_helper_call = self.mock_object(
            self.share_manager.access_helper, 'update_access_rules')
        self.share_manager.driver = mock.Mock()
        manager.CONF.delete_share_server_with_last_share = True

        self.share_manager.delete_share_instance(self.context,
                                                 share.instance['id'])

        mock_access_helper_call.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share.instance['id'],
            delete_all_rules=True, share_server=mock.ANY)
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
        share_network_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_net['id']
        )
        share_srv = db_utils.create_share_server(
            host=self.share_manager.host,
            share_network_subnets=[share_network_subnet]
        )
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'],
                                      share_type_id=share_type['id'])
        share_srv = db.share_server_get(self.context, share_srv['id'])
        mock_access_helper_call = self.mock_object(
            self.share_manager.access_helper, 'update_access_rules')
        self.share_manager.driver = mock.Mock()
        if side_effect == 'update_access':
            mock_access_helper_call.side_effect = exception.ManilaException
        if side_effect == 'delete_share':
            self.mock_object(self.share_manager.driver, 'delete_share',
                             mock.Mock(side_effect=Exception('fake')))
        self.mock_object(manager.LOG, 'error')
        manager.CONF.delete_share_server_with_last_share = True

        self.share_manager.delete_share_instance(
            self.context, share.instance['id'], force=force)

        mock_access_helper_call.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share.instance['id'],
            delete_all_rules=True, share_server=mock.ANY)
        self.share_manager.driver.teardown_server.assert_called_once_with(
            server_details=share_srv.get('backend_details'),
            security_services=[])
        self.assertEqual(force, manager.LOG.error.called)

    def test_delete_share_instance_last_on_server_deletion_disabled(self):
        share_net = db_utils.create_share_network()
        share_srv = db_utils.create_share_server(host=self.share_manager.host)
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'],
                                      share_type_id=share_type['id'])
        share_srv = db.share_server_get(self.context, share_srv['id'])

        manager.CONF.delete_share_server_with_last_share = False
        self.share_manager.driver = mock.Mock()
        mock_access_helper_call = self.mock_object(
            self.share_manager.access_helper, 'update_access_rules')
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value=share_srv))

        self.share_manager.delete_share_instance(self.context,
                                                 share.instance['id'])

        mock_access_helper_call.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share.instance['id'],
            delete_all_rules=True, share_server=share_srv)
        self.assertFalse(self.share_manager.driver.teardown_network.called)

    def test_delete_share_instance_not_last_on_server(self):
        share_net = db_utils.create_share_network()
        share_srv = db_utils.create_share_server(
            host=self.share_manager.host
        )
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'],
                                      share_type_id=share_type['id'])
        db_utils.create_share(share_network_id=share_net['id'],
                              share_server_id=share_srv['id'])
        share_srv = db.share_server_get(self.context, share_srv['id'])

        manager.CONF.delete_share_server_with_last_share = True
        self.share_manager.driver = mock.Mock()
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value=share_srv))
        mock_access_helper_call = self.mock_object(
            self.share_manager.access_helper, 'update_access_rules')

        self.share_manager.delete_share_instance(self.context,
                                                 share.instance['id'])

        mock_access_helper_call.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share.instance['id'],
            delete_all_rules=True, share_server=share_srv)
        self.assertFalse(self.share_manager.driver.teardown_network.called)

    @ddt.data('update_access', 'delete_share')
    def test_delete_share_instance_not_found(self, side_effect):
        share_net = db_utils.create_share_network()
        share_srv = db_utils.create_share_server(
            host=self.share_manager.host)
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_network_id=share_net['id'],
                                      share_server_id=share_srv['id'],
                                      share_type_id=share_type['id'])
        access = db_utils.create_access(share_id=share['id'])
        db_utils.create_share(share_network_id=share_net['id'],
                              share_server_id=share_srv['id'])
        share_srv = db.share_server_get(self.context, share_srv['id'])

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
            mock_access_helper_call = self.mock_object(
                self.share_manager.access_helper, 'update_access_rules',
                mock.Mock(side_effect=exception.ShareResourceNotFound(
                    share_id=share['id'])))
        if side_effect == 'delete_share':
            mock_access_helper_call = self.mock_object(
                self.share_manager.access_helper, 'update_access_rules',
                mock.Mock(return_value=None)
            )
            self.mock_object(
                self.share_manager.driver, 'delete_share',
                mock.Mock(side_effect=exception.ShareResourceNotFound(
                    share_id=share['id'])))

        self.mock_object(manager.LOG, 'warning')

        self.share_manager.delete_share_instance(self.context,
                                                 share.instance['id'])
        self.assertFalse(self.share_manager.driver.teardown_network.called)

        mock_access_helper_call.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share.instance['id'],
            delete_all_rules=True, share_server=share_srv)
        self.assertTrue(manager.LOG.warning.called)

    def test_setup_server(self):
        # Setup required test data
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = db_utils.create_share_network(id='fake_sn_id')
        share_net_subnets = [db_utils.create_share_network_subnet(
            id='fake_sns_id', share_network_id=share_network['id']
        )]
        share_server = db_utils.create_share_server(
            id='fake_id', share_network_subnets=share_net_subnets)
        network_info = {'security_services': []}
        for ss_type in constants.SECURITY_SERVICES_ALLOWED_TYPES:
            network_info['security_services'].append({
                'name': 'fake_name' + ss_type,
                'ou': 'fake_ou' + ss_type,
                'domain': 'fake_domain' + ss_type,
                'server': 'fake_server' + ss_type,
                'dns_ip': 'fake_dns_ip' + ss_type,
                'user': 'fake_user' + ss_type,
                'type': ss_type,
                'password': 'fake_password' + ss_type,
                'default_ad_site': 'fake_default_ad_site' + ss_type,
            })
        sec_services = network_info['security_services']
        server_info = {'fake_server_info_key': 'fake_server_info_value'}
        network_info['network_type'] = 'fake_network_type'

        # mock required stuff
        self.mock_object(self.share_manager.db,
                         'share_network_subnet_get_all_by_share_server_id',
                         mock.Mock(return_value=share_net_subnets))
        self.mock_object(self.share_manager.db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(self.share_manager.driver, 'allocate_network')
        self.mock_object(self.share_manager, '_form_server_setup_info',
                         mock.Mock(return_value=[network_info]))
        self.mock_object(self.share_manager, '_validate_segmentation_id')
        self.mock_object(self.share_manager.driver, 'setup_server',
                         mock.Mock(return_value=server_info))
        self.mock_object(self.share_manager.db,
                         'share_server_backend_details_set')
        self.mock_object(self.share_manager.db, 'share_server_update',
                         mock.Mock(return_value=share_server))

        # execute method _setup_server
        result = self.share_manager._setup_server(
            self.context, share_server, metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_called_once_with(
            self.context, share_net_subnets[0]['share_network_id'])
        (self.share_manager.db.share_network_subnet_get_all_by_share_server_id.
            assert_called_once_with(
                self.context, share_server['id']))
        self.share_manager.driver.allocate_network.assert_called_once_with(
            self.context, share_server, share_network,
            share_server['share_network_subnets'][0])
        self.share_manager._form_server_setup_info.assert_called_once_with(
            self.context, share_server, share_network, share_net_subnets)
        self.share_manager._validate_segmentation_id.assert_called_once_with(
            network_info)
        self.share_manager.driver.setup_server.assert_called_once_with(
            [network_info], metadata=metadata)
        (self.share_manager.db.share_server_backend_details_set.
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
            ]))
        self.share_manager.db.share_server_update.assert_called_once_with(
            self.context, share_server['id'],
            {'status': constants.STATUS_ACTIVE,
             'identifier': share_server['id']})

    def test_setup_server_server_info_not_present(self):
        # Setup required test data
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = {'id': 'fake_sn_id'}
        share_net_subnets = [{'id': 'fake_sns_id',
                             'share_network_id': share_network['id']}]
        share_server = {
            'id': 'fake_id',
            'share_network_subnets': share_net_subnets,
        }
        network_info = {
            'fake_network_info_key': 'fake_network_info_value',
            'security_services': [],
            'network_type': 'fake_network_type',
        }
        server_info = {}

        # mock required stuff
        self.mock_object(self.share_manager.db,
                         'share_network_subnet_get_all_by_share_server_id',
                         mock.Mock(return_value=share_net_subnets))
        self.mock_object(self.share_manager.db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(self.share_manager, '_form_server_setup_info',
                         mock.Mock(return_value=[network_info]))
        self.mock_object(self.share_manager.driver, 'setup_server',
                         mock.Mock(return_value=server_info))
        self.mock_object(self.share_manager.db, 'share_server_update',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager.driver, 'allocate_network')

        # execute method _setup_server
        result = self.share_manager._setup_server(
            self.context, share_server, metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_called_once_with(
            self.context, share_net_subnets[0]['share_network_id'])
        (self.share_manager.db.share_network_subnet_get_all_by_share_server_id.
            assert_called_once_with(
                self.context, share_server['id']))
        self.share_manager._form_server_setup_info.assert_called_once_with(
            self.context, share_server, share_network, share_net_subnets)
        self.share_manager.driver.setup_server.assert_called_once_with(
            [network_info], metadata=metadata)
        self.share_manager.db.share_server_update.assert_called_once_with(
            self.context, share_server['id'],
            {'status': constants.STATUS_ACTIVE,
             'identifier': share_server['id']})
        self.share_manager.driver.allocate_network.assert_called_once_with(
            self.context, share_server, share_network, share_net_subnets[0])

    def setup_server_raise_no_subnets(self):

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            self.share_manager._setup_server,
            self.context,
            {'share_network_subnets': []},
            {})

    def setup_server_raise_exception(self, detail_data_proper):
        # Setup required test data
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        server_info = {'details_key': 'value'}
        share_network = {'id': 'fake_sn_id'}
        share_net_subnets = [{'id': 'fake_sns_id',
                              'share_network_id': share_network['id']}]
        share_server = {
            'id': 'fake_id',
            'share_network_subnets': share_net_subnets
        }
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
        self.mock_object(self.share_manager.db,
                         'share_network_subnet_get_all_by_share_server_id',
                         mock.Mock(return_value=share_net_subnets))
        self.mock_object(self.share_manager.db, 'share_server_update')
        for m in ['deallocate_network', 'allocate_network']:
            self.mock_object(self.share_manager.driver, m)
        self.mock_object(self.share_manager, '_form_server_setup_info',
                         mock.Mock(return_value=[network_info]))
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
            metadata,
        )

        # verify results
        if detail_data_proper:
            (self.share_manager.db.share_server_backend_details_set.
                assert_called_once_with(
                    self.context, share_server['id'], server_info))
        self.share_manager._form_server_setup_info.assert_called_once_with(
            self.context, share_server, share_network, share_net_subnets)
        self.share_manager.db.share_server_update.assert_called_once_with(
            self.context, share_server['id'],
            {'status': constants.STATUS_ERROR})
        self.share_manager.db.share_network_get.assert_called_once_with(
            self.context, share_net_subnets[0]['share_network_id'])
        (self.share_manager.db.share_network_subnet_get_all_by_share_server_id.
            assert_called_once_with(
                self.context, share_server['id']))
        self.share_manager.driver.allocate_network.assert_has_calls([
            mock.call(self.context, share_server, share_network,
                      share_net_subnets[0])])
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

        share_net_subnets = [db_utils.create_share_network_subnet(
            id='fake_subnet_id', share_network_id='fake_share_net_id'
        )]
        share_server = db_utils.create_share_server(
            id='fake', share_network_subnets=share_net_subnets)
        details = get_server_details_from_data(data)
        metadata = {'fake_metadata_key': 'fake_metadata_value'}

        exc_mock = mock.Mock(side_effect=exception.ManilaException(**data))
        details_mock = mock.Mock(side_effect=exception.ManilaException())
        self.mock_object(self.share_manager.db, 'share_network_get',
                         exc_mock)
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
            metadata,
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
                self.assertEqual(1, mock_LOG.exception.call_count)

    def test_ensure_share_instance_pool_notexist_and_get_from_driver(self):
        fake_share_instance = {'host': 'host@backend', 'id': 1,
                               'status': constants.STATUS_AVAILABLE}
        fake_host_expected_value = 'fake_pool'
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.driver, 'get_pool',
                         mock.Mock(return_value='fake_pool'))

        host = self.share_manager._ensure_share_instance_has_pool(
            context.get_admin_context(), fake_share_instance)

        self.share_manager.db.share_instance_update.assert_any_call(
            mock.ANY, 1, {'host': 'host@backend#fake_pool'})
        self.assertEqual(fake_host_expected_value, host)

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
            security_services='fake_security_services'
        )
        fake_share_network_subnet = dict(
            id='fake_sns_id',
            segmentation_id='fake_segmentation_id',
            cidr='fake_cidr',
            neutron_net_id='fake_neutron_net_id',
            neutron_subnet_id='fake_neutron_subnet_id',
            network_type='fake_network_type',
            subnet_metadata={'fake_key': 'fake_value'})
        expected = [dict(
            server_id=fake_share_server['id'],
            segmentation_id=fake_share_network_subnet['segmentation_id'],
            cidr=fake_share_network_subnet['cidr'],
            neutron_net_id=fake_share_network_subnet['neutron_net_id'],
            neutron_subnet_id=fake_share_network_subnet['neutron_subnet_id'],
            security_services=fake_share_network['security_services'],
            network_allocations=(
                fake_network_allocations_get_for_share_server()),
            admin_network_allocations=(
                fake_network_allocations_get_for_share_server(label='admin')),
            backend_details=fake_share_server['backend_details'],
            network_type=fake_share_network_subnet['network_type'],
            subnet_metadata=fake_share_network_subnet['subnet_metadata'])]

        network_info = self.share_manager._form_server_setup_info(
            self.context, fake_share_server, fake_share_network,
            [fake_share_network_subnet])

        self.assertEqual(expected, network_info)
        (self.share_manager.db.network_allocations_get_for_share_server.
            assert_has_calls([
                mock.call(self.context, fake_share_server['id'],
                          label='admin'),
                mock.call(self.context, fake_share_server['id'],
                          label='user',
                          subnet_id=fake_share_network_subnet['id'])
            ]))

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

    @ddt.data("available", "error_deleting")
    def test_delete_expired_share(self, share_status):
        self.mock_object(db, 'get_all_expired_shares',
                         mock.Mock(return_value=[{"id": "share1",
                                                  "status": share_status}, ]))
        self.mock_object(db, 'share_update')
        self.mock_object(api.API, 'delete')
        self.share_manager.delete_expired_share(self.context)
        db.get_all_expired_shares.assert_called_once_with(self.context)
        share1 = {"id": "share1", "status": share_status}
        if share1["status"] == "error_deleting":
            db.share_update.assert_called_once_with(
                self.context, share1["id"], {'status': 'error'})
        api.API.delete.assert_called_once_with(
            self.context, share1)

    def test_delete_expired_transfers(self):
        self.mock_object(db, 'get_all_expired_transfers',
                         mock.Mock(return_value=[{"id": "transfer1",
                                                  "name": "test_tr"}, ]))
        self.mock_object(transfer_api.API, 'delete')
        self.share_manager.delete_expired_transfers(self.context)
        db.get_all_expired_transfers.assert_called_once_with(self.context)
        transfer1 = {"id": "transfer1", "name": "test_tr"}
        transfer_api.API.delete.assert_called_once_with(
            self.context, transfer_id=transfer1["id"])

    @ddt.data(True, False)
    def test_transfer_accept(self, clear_rules):
        share = db_utils.create_share(id="fake")
        self.mock_object(db, 'share_get', mock.Mock(return_value=share))
        update_access_rules_call = self.mock_object(
            self.share_manager.access_helper,
            'update_access_rules')
        transfer_accept_call = self.mock_object(self.share_manager.driver,
                                                'transfer_accept')
        instances, rules = self._setup_init_mocks()
        self.mock_object(self.share_manager.db,
                         'share_access_get_all_for_share',
                         mock.Mock(return_value=rules))
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_share',
                         mock.Mock(return_value=instances))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=instances[0]))
        self.mock_object(self.share_manager,
                         '_get_share_server',
                         mock.Mock(return_value=None))
        self.share_manager.transfer_accept(self.context, "fake_share_id",
                                           "fake_user_id", "fake_project_id",
                                           clear_rules)
        if clear_rules:
            update_access_rules_call.assert_called_with(
                self.context, instances[0]['id'], delete_all_rules=True)
            transfer_accept_call.assert_called_with(
                self.context, instances[0], "fake_user_id",
                "fake_project_id", access_rules=[],
                share_server=None)
        else:
            transfer_accept_call.assert_called_with(
                self.context, instances[0], "fake_user_id",
                "fake_project_id", access_rules=rules,
                share_server=None)

    def test_transfer_accept_driver_cannot_transfer_with_rules(self):
        shr_obj = db_utils.create_share()
        self.mock_object(db, 'share_get', mock.Mock(return_value=shr_obj))

        drv_exc = exception.DriverCannotTransferShareWithRules
        update_access_rules_call = self.mock_object(
            self.share_manager.access_helper,
            'update_access_rules')
        transfer_accept_call = self.mock_object(self.share_manager.driver,
                                                'transfer_accept',
                                                mock.Mock(side_effect=drv_exc))
        rules = [
            db_utils.create_access(share_id=shr_obj['id']),
            db_utils.create_access(share_id=shr_obj['id'])
        ]
        self.mock_object(self.share_manager.db,
                         'share_access_get_all_for_share',
                         mock.Mock(return_value=rules))
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_share',
                         mock.Mock(return_value=[shr_obj['instance']]))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=shr_obj['instance']))
        self.mock_object(self.share_manager,
                         '_get_share_server',
                         mock.Mock(return_value=None))

        self.assertRaises(exception.DriverCannotTransferShareWithRules,
                          self.share_manager.transfer_accept,
                          self.context, shr_obj['id'],
                          "fake_new_user_id", "fake_new_project_id",
                          False)
        transfer_accept_call.assert_called_with(
            self.context, shr_obj['instance'], "fake_new_user_id",
            "fake_new_project_id", access_rules=rules,
            share_server=None)
        update_access_rules_call.assert_not_called()
        self.share_manager.message_api.create.assert_called_once_with(
            self.context,
            message_field.Action.TRANSFER_ACCEPT,
            'fake_new_project_id',
            resource_type=message_field.Resource.SHARE,
            resource_id=shr_obj['id'],
            detail=message_field.Detail.DRIVER_FAILED_TRANSFER_ACCEPT)

    def test_transfer_accept_other_driver_exception(self):
        shr_obj = db_utils.create_share()
        self.mock_object(db, 'share_get', mock.Mock(return_value=shr_obj))

        drv_exc = exception.ShareBackendException(msg='fake_msg')
        update_access_rules_call = self.mock_object(
            self.share_manager.access_helper,
            'update_access_rules')
        transfer_accept_call = self.mock_object(self.share_manager.driver,
                                                'transfer_accept',
                                                mock.Mock(side_effect=drv_exc))
        rules = [
            db_utils.create_access(share_id=shr_obj['id']),
            db_utils.create_access(share_id=shr_obj['id'])
        ]
        self.mock_object(self.share_manager.db,
                         'share_access_get_all_for_share',
                         mock.Mock(return_value=rules))
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_share',
                         mock.Mock(return_value=[shr_obj['instance']]))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=shr_obj['instance']))
        self.mock_object(self.share_manager,
                         '_get_share_server',
                         mock.Mock(return_value=None))

        self.assertRaises(exception.ShareBackendException,
                          self.share_manager.transfer_accept,
                          self.context, shr_obj['id'],
                          "fake_new_user_id", "fake_new_project_id",
                          False)
        transfer_accept_call.assert_called_with(
            self.context, shr_obj['instance'], "fake_new_user_id",
            "fake_new_project_id", access_rules=rules,
            share_server=None)
        update_access_rules_call.assert_not_called()
        self.share_manager.message_api.create.assert_not_called()

    @mock.patch('manila.tests.fake_notifier.FakeNotifier._notify')
    def test_extend_share_invalid(self, mock_notify):
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
        share_id = share['id']
        reservations = {}

        mock_notify.assert_not_called()

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
            project_id=str(share['project_id']),
            user_id=str(share['user_id']),
            share_type_id=share_type['id'],
        )

    @mock.patch('manila.tests.fake_notifier.FakeNotifier._notify')
    def test_extend_share(self, mock_notify):
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
        share_id = share['id']
        new_size = 123
        shr_update = {
            'size': int(new_size),
            'status': constants.STATUS_AVAILABLE.lower()
        }
        reservations = {}
        fake_share_server = 'fake'

        mock_notify.assert_not_called()

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
            user_id=share['user_id'], share_type_id=share_type['id'])
        manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, shr_update
        )

        self.assert_notify_called(mock_notify,
                                  (['INFO', 'share.extend.start'],
                                   ['INFO', 'share.extend.end']))

    def test_shrink_share_not_supported(self):
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(size=2, share_type_id=share_type['id'])
        new_size = 1
        share_id = share['id']

        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager, 'driver')
        self.mock_object(self.share_manager.db, 'share_update')

        self.mock_object(quota.QUOTAS, 'reserve')
        self.mock_object(quota.QUOTAS, 'rollback')
        self.mock_object(self.share_manager.driver, 'shrink_share',
                         mock.Mock(side_effect=NotImplementedError))

        self.assertRaises(
            exception.ShareShrinkingError,
            self.share_manager.shrink_share, self.context, share_id, new_size)

        self.share_manager.driver.shrink_share.assert_called_once_with(
            utils.IsAMatcher(models.ShareInstance),
            new_size, share_server=None
        )

        self.share_manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, {'status': constants.STATUS_AVAILABLE}
        )

        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY, gigabytes=-1, project_id=share['project_id'],
            share_type_id=share_type['id'], user_id=share['user_id'],
        )
        quota.QUOTAS.rollback.assert_called_once_with(
            mock.ANY, mock.ANY, project_id=share['project_id'],
            share_type_id=share_type['id'], user_id=share['user_id'],
        )
        self.assertTrue(self.share_manager.db.share_get.called)

        self.share_manager.message_api.create.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            message_field.Action.SHRINK,
            share['project_id'],
            resource_type=message_field.Resource.SHARE,
            resource_id=share_id,
            detail=message_field.Detail.DRIVER_FAILED_SHRINK)

    @ddt.data((True, [{'id': 'fake'}]), (False, []))
    @ddt.unpack
    def test_shrink_share_quota_error(self, supports_replication,
                                      replicas_list):
        size = 5
        new_size = 1
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(size=size,
                                      share_type_id=share_type['id'])
        share_id = share['id']

        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(side_effect=Exception('fake')))
        self.mock_object(
            self.share_manager.db, 'share_replicas_get_all_by_share',
            mock.Mock(return_value=replicas_list))

        deltas = {}
        if supports_replication:
            deltas.update({'replica_gigabytes': new_size - size})

        self.assertRaises(
            exception.ShareShrinkingError,
            self.share_manager.shrink_share, self.context, share_id, new_size)

        quota.QUOTAS.reserve.assert_called_with(
            mock.ANY,
            project_id=str(share['project_id']),
            user_id=str(share['user_id']),
            share_type_id=share_type['id'],
            gigabytes=new_size - size,
            **deltas
        )
        self.assertTrue(self.share_manager.db.share_update.called)
        (self.share_manager.db.share_replicas_get_all_by_share
            .assert_called_once_with(mock.ANY, share['id']))

    @ddt.data({'exc': exception.InvalidShare("fake"),
               'status': constants.STATUS_SHRINKING_ERROR},
              {'exc': exception.ShareShrinkingPossibleDataLoss("fake"),
               'status': constants.STATUS_AVAILABLE})
    @ddt.unpack
    def test_shrink_share_invalid(self, exc, status):
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
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
            share_type_id=share_type['id'], user_id=share['user_id'],
        )
        quota.QUOTAS.rollback.assert_called_once_with(
            mock.ANY, mock.ANY, project_id=share['project_id'],
            share_type_id=share_type['id'], user_id=share['user_id'],
        )
        self.assertTrue(self.share_manager.db.share_get.called)

        if isinstance(exc, exception.ShareShrinkingPossibleDataLoss):
            self.share_manager.message_api.create.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                message_field.Action.SHRINK,
                share['project_id'],
                resource_type=message_field.Resource.SHARE,
                resource_id=share_id,
                detail=message_field.Detail.DRIVER_REFUSED_SHRINK)

    @ddt.data(True, False)
    def test_shrink_share(self, supports_replication):
        share_type = db_utils.create_share_type()
        share = db_utils.create_share(share_type_id=share_type['id'])
        share_id = share['id']
        new_size = 123
        shr_update = {
            'size': int(new_size),
            'status': constants.STATUS_AVAILABLE
        }
        fake_share_server = 'fake'
        size_decrease = int(share['size']) - new_size
        mock_notify = self.mock_object(fake_notifier.FakeNotifier, '_notify')
        replicas_list = []
        if supports_replication:
            replicas_list.append(share)
            replicas_list.append({'name': 'fake_replica'})

        mock_notify.assert_not_called()

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
        self.mock_object(manager.db, 'share_replicas_get_all_by_share',
                         mock.Mock(return_value=replicas_list))
        reservation_params = {
            'gigabytes': -size_decrease,
            'project_id': share['project_id'],
            'share_type_id': share_type['id'],
            'user_id': share['user_id'],
        }
        if supports_replication:
            reservation_params.update(
                {'replica_gigabytes': -size_decrease * 2})

        self.share_manager.shrink_share(self.context, share_id, new_size)

        self.assertTrue(manager._get_share_server.called)
        manager.driver.shrink_share.assert_called_once_with(
            utils.IsAMatcher(models.ShareInstance),
            new_size, share_server=fake_share_server
        )

        quota.QUOTAS.reserve.assert_called_once_with(
            mock.ANY, **reservation_params,
        )
        quota.QUOTAS.commit.assert_called_once_with(
            mock.ANY, mock.ANY, project_id=share['project_id'],
            share_type_id=share_type['id'], user_id=share['user_id'],
        )
        manager.db.share_update.assert_called_once_with(
            mock.ANY, share_id, shr_update
        )

        self.assert_notify_called(mock_notify,
                                  (['INFO', 'share.shrink.start'],
                                   ['INFO', 'share.shrink.end']))
        (self.share_manager.db.share_replicas_get_all_by_share.
            assert_called_once_with(mock.ANY, share['id']))

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

    def test_create_share_group(self):
        fake_group = {
            'id': 'fake_id',
            'availability_zone_id': 'fake_az',
        }
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.driver,
                         'create_share_group',
                         mock.Mock(return_value=None))

        self.share_manager.create_share_group(self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id', {
                'status': constants.STATUS_AVAILABLE,
                'created_at': mock.ANY,
                'consistent_snapshot_support': None,
                'availability_zone_id': fake_group['availability_zone_id'],
            }
        )

    def test_create_cg_with_share_network_driver_not_handles_servers(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=False))
        cg_id = 'fake_group_id'
        share_network_id = 'fake_sn'
        fake_group = {'id': 'fake_id', 'share_network_id': share_network_id}
        self.mock_object(
            self.share_manager.db, 'share_group_get',
            mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_update')

        self.assertRaises(
            exception.ManilaException,
            self.share_manager.create_share_group, self.context, cg_id)

        self.share_manager.db.share_group_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), cg_id)
        self.share_manager.db.share_group_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), cg_id,
            {'status': constants.STATUS_ERROR})

    def test_create_sg_with_share_network_driver_handles_servers(self):
        manager.CONF.set_default('driver_handles_share_servers', True)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=True))
        share_network_id = 'fake_sn'
        fake_group = {
            'id': 'fake_id',
            'share_network_id': share_network_id,
            'host': "fake_host",
            'availability_zone_id': 'fake_az',
        }
        fake_subnet = {
            'id': 'fake_subnet_id'
        }
        self.mock_object(
            self.share_manager.db, 'share_group_get',
            mock.Mock(return_value=fake_group))
        self.mock_object(
            self.share_manager.db, 'share_group_update',
            mock.Mock(return_value=fake_group))
        self.mock_object(
            self.share_manager.db,
            'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=[fake_subnet])
        )
        self.mock_object(
            self.share_manager, '_provide_share_server_for_share_group',
            mock.Mock(return_value=({}, fake_group)))
        self.mock_object(
            self.share_manager.driver, 'create_share_group',
            mock.Mock(return_value=None))

        self.share_manager.create_share_group(self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id', {
                'status': constants.STATUS_AVAILABLE,
                'created_at': mock.ANY,
                'consistent_snapshot_support': None,
                'availability_zone_id': fake_group['availability_zone_id'],
            }
        )

    def test_create_share_group_with_update(self):
        fake_group = {
            'id': 'fake_id',
            'availability_zone_id': 'fake_az',
        }
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.driver,
                         'create_share_group',
                         mock.Mock(return_value={'foo': 'bar'}))

        self.share_manager.create_share_group(self.context, "fake_id")

        (self.share_manager.db.share_group_update.
            assert_any_call(mock.ANY, 'fake_id', {'foo': 'bar'}))
        self.share_manager.db.share_group_update.assert_any_call(
            mock.ANY, 'fake_id', {
                'status': constants.STATUS_AVAILABLE,
                'created_at': mock.ANY,
                'consistent_snapshot_support': None,
                'availability_zone_id': fake_group['availability_zone_id'],
            }
        )

    def test_create_share_group_with_error(self):
        fake_group = {
            'id': 'fake_id',
            'availability_zone_id': 'fake_az',
        }
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.driver,
                         'create_share_group',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error,
                          self.share_manager.create_share_group,
                          self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id', {
                'status': constants.STATUS_ERROR,
                'consistent_snapshot_support': None,
                'availability_zone_id': fake_group['availability_zone_id'],
            }
        )

    def test_create_share_group_from_sg_snapshot(self):
        fake_group = {
            'id': 'fake_id',
            'source_share_group_snapshot_id': 'fake_snap_id',
            'shares': [],
            'share_server_id': 'fake_ss_id',
            'availability_zone_id': 'fake_az',
        }
        fake_sn = {'id': 'fake_sn_id'}
        fake_sns = {'id': 'fake_sns_id', 'share_network_id': fake_sn['id']}
        fake_ss = {'id': 'fake_ss_id', 'share_network_subnets': [fake_sns],
                   'share_network_id': 'fake_sn_id'}
        fake_snap = {'id': 'fake_snap_id', 'share_group_snapshot_members': [],
                     'share_group': {'share_server_id': fake_ss['id']}}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(
                             return_value=fake_ss))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        mock_create_sg_from_sg_snap = self.mock_object(
            self.share_manager.driver,
            'create_share_group_from_share_group_snapshot',
            mock.Mock(return_value=(None, None)))

        self.share_manager.create_share_group(self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id',
            {'status': constants.STATUS_AVAILABLE,
             'created_at': mock.ANY,
             'availability_zone_id': fake_group['availability_zone_id'],
             'consistent_snapshot_support': None})
        self.share_manager.db.share_server_get(mock.ANY, 'fake_ss_id')
        mock_create_sg_from_sg_snap.assert_called_once_with(
            mock.ANY, fake_group, fake_snap, share_server=fake_ss)

    def test_create_sg_snapshot_share_network_driver_not_handles_servers(self):
        manager.CONF.set_default('driver_handles_share_servers', False)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=False))
        sg_id = 'fake_share_group_id'
        share_network_id = 'fake_sn'
        fake_group = {
            'id': 'fake_id',
            'source_share_group_snapshot_id': 'fake_snap_id',
            'shares': [],
            'share_network_id': share_network_id,
            'host': "fake_host",
        }
        self.mock_object(
            self.share_manager.db, 'share_group_get',
            mock.Mock(return_value=fake_group))
        fake_snap = {'id': 'fake_snap_id', 'share_group_snapshot_members': []}
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'share_group_update')

        self.assertRaises(exception.ManilaException,
                          self.share_manager.create_share_group,
                          self.context, sg_id)

        self.share_manager.db.share_group_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), sg_id)
        self.share_manager.db.share_group_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), sg_id,
            {'status': constants.STATUS_ERROR})

    def test_create_sg_snapshot_share_network_without_subnets(self):
        manager.CONF.set_default('driver_handles_share_servers', True)
        self.mock_object(
            self.share_manager.driver.configuration, 'safe_get',
            mock.Mock(return_value=True))
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_share_group_id',
                         mock.Mock(return_value=[]))
        fake_group = {
            'id': 'fake_id',
            'source_share_group_snapshot_id': 'fake_snap_id',
            'shares': [],
            'share_network_id': 'fake_sn',
            'host': "fake_host",
        }
        self.mock_object(
            self.share_manager.db, 'share_group_get',
            mock.Mock(return_value=fake_group))
        fake_snap = {'id': 'fake_snap_id', 'share_group_snapshot_members': []}
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager, '_get_az_for_share_group',
                         mock.Mock(return_value='az'))
        self.mock_object(
            self.share_manager.db,
            'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=[]))

        self.assertRaises(exception.ShareNetworkSubnetNotFound,
                          self.share_manager.create_share_group,
                          self.context, 'fake_share_group_id')

    def test_create_share_group_from_sg_snapshot_share_network_dhss(self):
        manager.CONF.set_default('driver_handles_share_servers', True)
        self.mock_object(self.share_manager.driver.configuration, 'safe_get',
                         mock.Mock(return_value=True))
        share_network_id = 'fake_sn'
        share_network_subnet = {
            'id': 'fake_subnet_id'
        }
        fake_group = {
            'id': 'fake_id',
            'source_share_group_snapshot_id': 'fake_snap_id',
            'shares': [],
            'share_network_id': share_network_id,
            'availability_zone_id': 'fake_az',
        }
        fake_snap = {'id': 'fake_snap_id', 'share_group_snapshot_members': []}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        self.mock_object(
            self.share_manager.db,
            'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=share_network_subnet))
        self.mock_object(
            self.share_manager, '_provide_share_server_for_share_group',
            mock.Mock(return_value=({}, fake_group)))
        self.mock_object(
            self.share_manager.driver,
            'create_share_group_from_share_group_snapshot',
            mock.Mock(return_value=(None, None)))

        self.share_manager.create_share_group(self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id',
            {'status': constants.STATUS_AVAILABLE,
             'created_at': mock.ANY,
             'consistent_snapshot_support': None,
             'availability_zone_id': fake_group['availability_zone_id']})

    def test_create_share_group_from_share_group_snapshot_with_update(self):
        fake_group = {
            'id': 'fake_id',
            'source_share_group_snapshot_id': 'fake_snap_id',
            'shares': [],
            'availability_zone_id': 'fake_az',
        }
        fake_snap = {'id': 'fake_snap_id', 'share_group_snapshot_members': []}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.driver,
                         'create_share_group_from_share_group_snapshot',
                         mock.Mock(return_value=({'foo': 'bar'}, None)))

        self.share_manager.create_share_group(self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_any_call(
            mock.ANY, 'fake_id', {'foo': 'bar'})
        self.share_manager.db.share_group_update.assert_any_call(
            mock.ANY, 'fake_id', {
                'status': constants.STATUS_AVAILABLE,
                'created_at': mock.ANY,
                'consistent_snapshot_support': None,
                'availability_zone_id': fake_group['availability_zone_id'],
            }
        )

    @ddt.data(constants.STATUS_AVAILABLE,
              constants.STATUS_CREATING_FROM_SNAPSHOT,
              None)
    def test_create_share_group_from_sg_snapshot_with_share_update_status(
            self, share_status):
        fake_share = {'id': 'fake_share_id'}
        # if share_status is not None:
        #     fake_share.update({'status': share_status})

        fake_export_locations = ['my_export_location']
        fake_group = {
            'id': 'fake_id',
            'source_share_group_snapshot_id': 'fake_snap_id',
            'shares': [fake_share],
            'availability_zone_id': 'fake_az',
        }
        fake_snap = {'id': 'fake_snap_id', 'share_group_snapshot_members': []}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'share_group_update')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db,
                         'share_export_locations_update')

        fake_share_update = {'id': fake_share['id'],
                             'foo': 'bar',
                             'export_locations': fake_export_locations}
        if share_status is not None:
            fake_share_update.update({'status': share_status})

        self.mock_object(self.share_manager.driver,
                         'create_share_group_from_share_group_snapshot',
                         mock.Mock(return_value=(None, [fake_share_update])))

        self.share_manager.create_share_group(self.context, "fake_id")

        exp_progress = (
            '0%' if share_status == constants.STATUS_CREATING_FROM_SNAPSHOT
            else '100%')
        self.share_manager.db.share_instance_update.assert_any_call(
            mock.ANY,
            'fake_share_id',
            {'foo': 'bar',
             'status': share_status or constants.STATUS_AVAILABLE,
             'progress': exp_progress})
        self.share_manager.db.share_export_locations_update.assert_any_call(
            mock.ANY, 'fake_share_id', fake_export_locations)
        self.share_manager.db.share_group_update.assert_any_call(
            mock.ANY, 'fake_id', {
                'status': constants.STATUS_AVAILABLE,
                'created_at': mock.ANY,
                'consistent_snapshot_support': None,
                'availability_zone_id': fake_group['availability_zone_id'],
            }
        )

    def test_create_share_group_from_sg_snapshot_with_error(self):
        fake_group = {
            'id': 'fake_id',
            'source_share_group_snapshot_id': 'fake_snap_id',
            'shares': [],
            'availability_zone_id': 'fake_az',
        }
        fake_snap = {'id': 'fake_snap_id', 'share_group_snapshot_members': []}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_share_group_id',
                         mock.Mock(return_value=[]))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.driver,
                         'create_share_group_from_share_group_snapshot',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error,
                          self.share_manager.create_share_group,
                          self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id', {
                'status': constants.STATUS_ERROR,
                'consistent_snapshot_support': None,
                'availability_zone_id': fake_group['availability_zone_id'],
            }
        )

    def test_create_share_group_from_sg_snapshot_with_invalid_status(self):
        fake_share = {'id': 'fake_share_id',
                      'status': constants.STATUS_CREATING}
        fake_export_locations = ['my_export_location']
        fake_group = {
            'id': 'fake_id',
            'source_share_group_snapshot_id': 'fake_snap_id',
            'shares': [fake_share],
            'availability_zone_id': 'fake_az',
        }
        fake_snap = {'id': 'fake_snap_id', 'share_group_snapshot_members': []}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_share_group_id',
                         mock.Mock(return_value=[]))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        fake_share_update_list = [{'id': fake_share['id'],
                                   'status': fake_share['status'],
                                   'foo': 'bar',
                                   'export_locations': fake_export_locations}]
        self.mock_object(self.share_manager.driver,
                         'create_share_group_from_share_group_snapshot',
                         mock.Mock(
                             return_value=(None, fake_share_update_list)))

        self.assertRaises(exception.InvalidShareInstance,
                          self.share_manager.create_share_group,
                          self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id', {
                'status': constants.STATUS_ERROR,
                'consistent_snapshot_support': None,
                'availability_zone_id': fake_group['availability_zone_id'],
            }
        )

    def test_create_share_group_from_sg_snapshot_with_share_error(self):
        fake_share = {'id': 'fake_share_id'}
        fake_group = {
            'id': 'fake_id',
            'source_share_group_snapshot_id': 'fake_snap_id',
            'shares': [fake_share],
            'availability_zone_id': 'fake_az',
        }
        fake_snap = {'id': 'fake_snap_id', 'share_group_snapshot_members': []}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_share_group_id',
                         mock.Mock(return_value=[fake_share]))
        self.mock_object(self.share_manager.db, 'share_group_update')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.driver,
                         'create_share_group_from_share_group_snapshot',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error,
                          self.share_manager.create_share_group,
                          self.context, "fake_id")

        self.share_manager.db.share_instance_update.assert_any_call(
            mock.ANY, 'fake_share_id', {'status': constants.STATUS_ERROR})
        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id', {
                'status': constants.STATUS_ERROR,
                'consistent_snapshot_support': None,
                'availability_zone_id': fake_group['availability_zone_id'],
            }
        )

    def test_delete_share_group(self):
        fake_group = {'id': 'fake_id'}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_destroy',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.driver,
                         'delete_share_group',
                         mock.Mock(return_value=None))

        self.share_manager.delete_share_group(self.context, "fake_id")

        self.share_manager.db.share_group_destroy.assert_called_once_with(
            mock.ANY, 'fake_id')

    def test_delete_share_group_with_update(self):
        fake_group = {'id': 'fake_id'}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_destroy',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.driver,
                         'delete_share_group',
                         mock.Mock(return_value={'foo': 'bar'}))

        self.share_manager.delete_share_group(self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id', {'foo': 'bar'})
        self.share_manager.db.share_group_destroy.assert_called_once_with(
            mock.ANY, 'fake_id')

    def test_delete_share_group_with_error(self):
        fake_group = {'id': 'fake_id'}
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.db, 'share_group_update',
                         mock.Mock(return_value=fake_group))
        self.mock_object(self.share_manager.driver,
                         'delete_share_group',
                         mock.Mock(side_effect=exception.Error))

        self.assertRaises(exception.Error,
                          self.share_manager.delete_share_group,
                          self.context, "fake_id")

        self.share_manager.db.share_group_update.assert_called_once_with(
            mock.ANY, 'fake_id', {'status': constants.STATUS_ERROR})

    def test_create_share_group_snapshot(self):
        fake_snap = {
            'id': 'fake_snap_id',
            'share_group': {},
            'share_group_snapshot_members': [],
        }
        self.mock_object(
            self.share_manager.db, 'share_group_snapshot_get',
            mock.Mock(return_value=fake_snap))
        mock_sg_snap_update = self.mock_object(
            self.share_manager.db, 'share_group_snapshot_update',
            mock.Mock(return_value=fake_snap))
        self.mock_object(
            self.share_manager.driver,
            'create_share_group_snapshot',
            mock.Mock(return_value=(None, None)))

        self.share_manager.create_share_group_snapshot(
            self.context, fake_snap['id'])

        mock_sg_snap_update.assert_called_once_with(
            mock.ANY, fake_snap['id'],
            {'status': constants.STATUS_AVAILABLE, 'updated_at': mock.ANY})

    def test_create_share_group_snapshot_with_update(self):
        fake_snap = {'id': 'fake_snap_id', 'share_group': {},
                     'share_group_snapshot_members': []}
        self.mock_object(self.share_manager.db, 'share_group_snapshot_get',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.db, 'share_group_snapshot_update',
                         mock.Mock(return_value=fake_snap))
        self.mock_object(self.share_manager.driver,
                         'create_share_group_snapshot',
                         mock.Mock(return_value=({'foo': 'bar'}, None)))

        self.share_manager.create_share_group_snapshot(
            self.context, fake_snap['id'])

        self.share_manager.db.share_group_snapshot_update.assert_any_call(
            mock.ANY, 'fake_snap_id', {'foo': 'bar'})
        self.share_manager.db.share_group_snapshot_update.assert_any_call(
            mock.ANY, fake_snap['id'],
            {'status': constants.STATUS_AVAILABLE, 'updated_at': mock.ANY})

    def test_create_share_group_snapshot_with_member_update(self):
        fake_member1 = {'id': 'fake_member_id_1', 'share_instance_id': 'si_1'}
        fake_member2 = {'id': 'fake_member_id_2', 'share_instance_id': 'si_2'}
        fake_member3 = {'id': 'fake_member_id_3', 'share_instance_id': 'si_3'}
        fake_member_update1 = {
            'id': fake_member1['id'],
            'provider_location': 'fake_provider_location_1',
            'size': 13,
            'export_locations': ['fake_el_1_1', 'fake_el_1_2'],
            'should_not_be_used_k1': 'should_not_be_used_v1',
        }
        fake_member_update2 = {
            'id': fake_member2['id'],
            'provider_location': 'fake_provider_location_2',
            'size': 31,
            'export_locations': ['fake_el_2_1', 'fake_el_2_2'],
            'status': 'fake_status_for_update',
            'should_not_be_used_k2': 'should_not_be_used_k2',
        }
        fake_member_update3 = {
            'provider_location': 'fake_provider_location_3',
            'size': 42,
            'export_locations': ['fake_el_3_1', 'fake_el_3_2'],
            'should_not_be_used_k3': 'should_not_be_used_k3',
        }
        expected_member_update1 = {
            'id': fake_member_update1['id'],
            'provider_location': fake_member_update1['provider_location'],
            'size': fake_member_update1['size'],
        }
        expected_member_update2 = {
            'id': fake_member_update2['id'],
            'provider_location': fake_member_update2['provider_location'],
            'size': fake_member_update2['size'],
            'status': fake_member_update2['status'],
        }
        fake_snap = {
            'id': 'fake_snap_id',
            'share_group': {},
            'share_group_snapshot_members': [
                fake_member1, fake_member2, fake_member3],
        }
        self.mock_object(
            self.share_manager.db, 'share_group_snapshot_get',
            mock.Mock(return_value=fake_snap))
        mock_sg_snapshot_update = self.mock_object(
            self.share_manager.db, 'share_group_snapshot_update',
            mock.Mock(return_value=fake_snap))
        mock_sg_snapshot_member_update = self.mock_object(
            self.share_manager.db, 'share_group_snapshot_member_update')
        self.mock_object(
            self.share_manager.db, 'share_instance_get',
            mock.Mock(return_value={'id': 'blah'}))
        self.mock_object(
            timeutils, 'utcnow', mock.Mock(side_effect=range(1, 10)))
        mock_driver_create_sg_snapshot = self.mock_object(
            self.share_manager.driver, 'create_share_group_snapshot',
            mock.Mock(return_value=(
                None, [fake_member_update1, fake_member_update2,
                       fake_member_update3])))

        self.share_manager.create_share_group_snapshot(
            self.context, fake_snap['id'])

        mock_driver_create_sg_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            fake_snap, share_server=None)
        mock_sg_snapshot_update.assert_called_once_with(
            mock.ANY, fake_snap['id'],
            {'status': constants.STATUS_AVAILABLE, 'updated_at': mock.ANY})
        mock_sg_snapshot_member_update.assert_has_calls([
            mock.call(
                utils.IsAMatcher(context.RequestContext),
                expected_member_update1['id'],
                {'provider_location': expected_member_update1[
                    'provider_location'],
                 'size': expected_member_update1['size'],
                 'updated_at': 1,
                 'status': manager.constants.STATUS_AVAILABLE}),
            mock.call(
                utils.IsAMatcher(context.RequestContext),
                expected_member_update2['id'],
                {'provider_location': expected_member_update2[
                    'provider_location'],
                 'size': expected_member_update2['size'],
                 'updated_at': 1,
                 'status': expected_member_update2['status']}),
        ])

    def test_create_group_snapshot_with_error(self):
        fake_snap = {'id': 'fake_snap_id', 'share_group': {},
                     'share_group_snapshot_members': []}
        self.mock_object(
            self.share_manager.db, 'share_group_snapshot_get',
            mock.Mock(return_value=fake_snap))
        mock_sg_snap_update = self.mock_object(
            self.share_manager.db, 'share_group_snapshot_update',
            mock.Mock(return_value=fake_snap))
        self.mock_object(
            self.share_manager.driver,
            'create_share_group_snapshot',
            mock.Mock(side_effect=exception.Error))

        self.assertRaises(
            exception.Error,
            self.share_manager.create_share_group_snapshot,
            self.context, fake_snap['id'])

        mock_sg_snap_update.assert_called_once_with(
            mock.ANY, fake_snap['id'], {'status': constants.STATUS_ERROR})

    def test_connection_get_info(self):
        share_instance = {'share_server_id': 'fake_server_id'}
        share_instance_id = 'fake_id'
        share_server = 'fake_share_server'
        connection_info = 'fake_info'

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=share_instance))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager.driver, 'connection_get_info',
                         mock.Mock(return_value=connection_info))

        # run
        result = self.share_manager.connection_get_info(
            self.context, share_instance_id)

        # asserts
        self.assertEqual(connection_info, result)

        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, share_instance_id, with_share_data=True)

        self.share_manager.driver.connection_get_info.assert_called_once_with(
            self.context, share_instance, share_server)

    @ddt.data(True, False)
    def test_migration_start(self, success):

        instance = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_AVAILABLE,
            share_server_id='fake_server_id',
            host='fake@backend#pool')
        share = db_utils.create_share(id='fake_id', instances=[instance])
        fake_service = {'availability_zone_id': 'fake_az_id'}
        host = 'fake2@backend#pool'

        # mocks
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=instance))
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager, '_migration_start_driver',
                         mock.Mock(return_value=success))
        self.mock_object(self.share_manager.db, 'service_get_by_args',
                         mock.Mock(return_value=fake_service))

        if not success:
            self.mock_object(
                self.share_manager, '_migration_start_host_assisted')

        # run
        self.share_manager.migration_start(
            self.context, 'fake_id', host, False, False, False, False, False,
            'fake_net_id', 'fake_type_id')

        # asserts
        self.share_manager.db.share_get.assert_called_once_with(
            self.context, share['id'])
        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, instance['id'], with_share_data=True)

        share_update_calls = [
            mock.call(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS}),
        ]

        if not success:
            share_update_calls.append(mock.call(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS}))

        self.share_manager.db.share_update.assert_has_calls(share_update_calls)
        self.share_manager._migration_start_driver.assert_called_once_with(
            self.context, share, instance, host, False, False, False, False,
            'fake_net_id', 'fake_az_id', 'fake_type_id')
        if not success:
            (self.share_manager._migration_start_host_assisted.
                assert_called_once_with(
                    self.context, share, instance, host, 'fake_net_id',
                    'fake_az_id', 'fake_type_id'))
        self.share_manager.db.service_get_by_args.assert_called_once_with(
            self.context, 'fake2@backend', 'manila-share')

    @ddt.data({'writable': False, 'preserve_metadata': False,
               'nondisruptive': False, 'preserve_snapshots': True,
               'has_snapshots': False},
              {'writable': False, 'preserve_metadata': False,
               'nondisruptive': True, 'preserve_snapshots': False,
               'has_snapshots': False},
              {'writable': False, 'preserve_metadata': True,
               'nondisruptive': False, 'preserve_snapshots': False,
               'has_snapshots': False},
              {'writable': True, 'preserve_metadata': False,
               'nondisruptive': False, 'preserve_snapshots': False,
               'has_snapshots': False},
              {'writable': False, 'preserve_metadata': False,
               'nondisruptive': False, 'preserve_snapshots': False,
               'has_snapshots': True}
              )
    @ddt.unpack
    def test_migration_start_prevent_host_assisted(
            self, writable, preserve_metadata, nondisruptive,
            preserve_snapshots, has_snapshots):

        share = db_utils.create_share()
        instance = share.instance
        host = 'fake@backend#pool'
        fake_service = {'availability_zone_id': 'fake_az_id'}
        if has_snapshots:
            snapshot = db_utils.create_snapshot(share_id=share['id'])
            self.mock_object(
                self.share_manager.db, 'share_snapshot_get_all_for_share',
                mock.Mock(return_value=[snapshot]))

        # mocks
        self.mock_object(self.share_manager, '_reset_read_only_access_rules')
        self.mock_object(self.share_manager.db, 'service_get_by_args',
                         mock.Mock(return_value=fake_service))
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))

        # run
        self.assertRaises(
            exception.ShareMigrationFailed, self.share_manager.migration_start,
            self.context, 'share_id', host, True, writable, preserve_metadata,
            nondisruptive, preserve_snapshots, 'fake_net_id')

        self.share_manager.db.share_update.assert_has_calls([
            mock.call(
                self.context, 'share_id',
                {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS}),
            mock.call(
                self.context, 'share_id',
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR}),
        ])
        self.share_manager.db.share_instance_update.assert_called_once_with(
            self.context, instance['id'],
            {'status': constants.STATUS_AVAILABLE})
        self.share_manager.db.share_get.assert_called_once_with(
            self.context, 'share_id')
        self.share_manager.db.service_get_by_args.assert_called_once_with(
            self.context, 'fake@backend', 'manila-share')
        (self.share_manager._reset_read_only_access_rules.
         assert_called_once_with(self.context, instance['id']))

    def test_migration_start_exception(self):

        instance = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_AVAILABLE,
            share_server_id='fake_server_id',
            host='fake@backend#pool')
        share = db_utils.create_share(id='fake_id', instances=[instance])
        host = 'fake2@backend#pool'
        fake_service = {'availability_zone_id': 'fake_az_id'}

        # mocks
        self.mock_object(self.share_manager.db, 'service_get_by_args',
                         mock.Mock(return_value=fake_service))
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=instance))
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager, '_migration_start_driver',
                         mock.Mock(side_effect=Exception('fake_exc_1')))
        self.mock_object(self.share_manager, '_migration_start_host_assisted',
                         mock.Mock(side_effect=Exception('fake_exc_2')))
        self.mock_object(self.share_manager, '_reset_read_only_access_rules')

        # run
        self.assertRaises(
            exception.ShareMigrationFailed,
            self.share_manager.migration_start,
            self.context, 'fake_id', host, False, False, False, False, False,
            'fake_net_id', 'fake_type_id')

        # asserts
        self.share_manager.db.share_get.assert_called_once_with(
            self.context, share['id'])
        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, instance['id'], with_share_data=True)

        share_update_calls = [
            mock.call(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS}),
            mock.call(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
        ]

        (self.share_manager._reset_read_only_access_rules.
         assert_called_once_with(self.context, instance['id']))
        self.share_manager.db.share_update.assert_has_calls(share_update_calls)
        self.share_manager.db.share_instance_update.assert_called_once_with(
            self.context, instance['id'],
            {'status': constants.STATUS_AVAILABLE})
        self.share_manager._migration_start_driver.assert_called_once_with(
            self.context, share, instance, host, False, False, False, False,
            'fake_net_id', 'fake_az_id', 'fake_type_id')
        self.share_manager.db.service_get_by_args.assert_called_once_with(
            self.context, 'fake2@backend', 'manila-share')

    @ddt.data(None, Exception('fake'))
    def test__migration_start_host_assisted(self, exc):
        share_server = db_utils.create_share_server()
        instance = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_AVAILABLE,
            share_server_id=share_server['id'])
        new_instance = db_utils.create_share_instance(
            share_id='new_fake_id',
            status=constants.STATUS_AVAILABLE)
        share = db_utils.create_share(id='fake_id', instances=[instance])
        src_connection_info = 'src_fake_info'
        dest_connection_info = 'dest_fake_info'
        instance_updates = [
            mock.call(
                self.context, instance['id'],
                {'cast_rules_to_readonly': True})
        ]
        # mocks
        helper = mock.Mock()
        self.mock_object(migration_api, 'ShareMigrationHelper',
                         mock.Mock(return_value=helper))
        self.mock_object(helper, 'cleanup_new_instance')
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager.db, 'share_instance_update',
                         mock.Mock(return_value=share_server))
        self.mock_object(self.share_manager.access_helper,
                         'get_and_update_share_instance_access_rules')
        self.mock_object(self.share_manager.access_helper,
                         'update_access_rules')
        self.mock_object(utils, 'wait_for_access_update')

        if exc is None:
            self.mock_object(helper,
                             'create_instance_and_wait',
                             mock.Mock(return_value=new_instance))
            self.mock_object(self.share_manager.driver, 'connection_get_info',
                             mock.Mock(return_value=src_connection_info))
            self.mock_object(rpcapi.ShareAPI, 'connection_get_info',
                             mock.Mock(return_value=dest_connection_info))
            self.mock_object(data_rpc.DataAPI, 'migration_start',
                             mock.Mock(side_effect=Exception('fake')))
            self.mock_object(helper, 'cleanup_new_instance')
            instance_updates.append(
                mock.call(self.context, new_instance['id'],
                          {'status': constants.STATUS_MIGRATING_TO}))
        else:
            self.mock_object(helper, 'create_instance_and_wait',
                             mock.Mock(side_effect=exc))

        # run
        self.assertRaises(
            exception.ShareMigrationFailed,
            self.share_manager._migration_start_host_assisted,
            self.context, share, instance, 'fake_host', 'fake_net_id',
            'fake_az_id', 'fake_type_id')

        # asserts
        self.share_manager.db.share_server_get.assert_has_calls([
            mock.call(utils.IsAMatcher(context.RequestContext),
                      instance['share_server_id']),
            mock.call(utils.IsAMatcher(context.RequestContext),
                      instance['share_server_id'])
            ])
        (self.share_manager.access_helper.update_access_rules.
         assert_called_once_with(
             self.context, instance['id'], share_server=share_server))
        helper.create_instance_and_wait.assert_called_once_with(
            share, 'fake_host', 'fake_net_id', 'fake_az_id', 'fake_type_id')
        utils.wait_for_access_update.assert_called_once_with(
            self.context, self.share_manager.db, instance,
            self.share_manager.migration_wait_access_rules_timeout)

        if exc is None:
            (self.share_manager.driver.connection_get_info.
                assert_called_once_with(self.context, instance, share_server))
            rpcapi.ShareAPI.connection_get_info.assert_called_once_with(
                self.context, new_instance)
            data_rpc.DataAPI.migration_start.assert_called_once_with(
                self.context, share['id'], ['lost+found'], instance['id'],
                new_instance['id'], src_connection_info, dest_connection_info)
            helper.cleanup_new_instance.assert_called_once_with(new_instance)

    @ddt.data({'share_network_id': 'fake_net_id', 'exc': None,
               'has_snapshots': True},
              {'share_network_id': None, 'exc': Exception('fake'),
               'has_snapshots': True},
              {'share_network_id': None, 'exc': None, 'has_snapshots': False})
    @ddt.unpack
    def test__migration_start_driver(
            self, exc, share_network_id, has_snapshots):
        fake_dest_host = 'fake_host'
        src_server = db_utils.create_share_server()
        if share_network_id:
            dest_server = db_utils.create_share_server()
        else:
            dest_server = None
        share = db_utils.create_share(
            id='fake_id',
            share_server_id='fake_src_server_id',
            share_network_id=share_network_id)
        migrating_instance = db_utils.create_share_instance(
            share_id='fake_id',
            share_network_id=share_network_id)
        if has_snapshots:
            snapshot = db_utils.create_snapshot(
                status=(constants.STATUS_AVAILABLE if not exc
                        else constants.STATUS_ERROR),
                share_id=share['id'])
            migrating_snap_instance = db_utils.create_snapshot(
                status=constants.STATUS_MIGRATING,
                share_id=share['id'])
            dest_snap_instance = db_utils.create_snapshot_instance(
                status=constants.STATUS_AVAILABLE,
                snapshot_id=snapshot['id'],
                share_instance_id=migrating_instance['id'])
            snapshot_mappings = {snapshot.instance['id']: dest_snap_instance}
        else:
            snapshot_mappings = {}
        src_instance = share.instance
        compatibility = {
            'compatible': True,
            'writable': False,
            'preserve_metadata': False,
            'nondisruptive': False,
            'preserve_snapshots': has_snapshots,
        }

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=migrating_instance))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=src_server))
        self.mock_object(self.share_manager.driver,
                         'migration_check_compatibility',
                         mock.Mock(return_value=compatibility))
        self.mock_object(
            api.API, 'create_share_instance_and_get_request_spec',
            mock.Mock(return_value=({}, migrating_instance)))
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(rpcapi.ShareAPI, 'provide_share_server',
                         mock.Mock(return_value='fake_dest_share_server_id'))
        self.mock_object(rpcapi.ShareAPI, 'create_share_server')
        self.mock_object(
            migration_api.ShareMigrationHelper, 'wait_for_share_server',
            mock.Mock(return_value=dest_server))
        self.mock_object(
            self.share_manager.db, 'share_snapshot_get_all_for_share',
            mock.Mock(return_value=[snapshot] if has_snapshots else []))
        if has_snapshots:
            self.mock_object(
                self.share_manager.db, 'share_snapshot_instance_create',
                mock.Mock(return_value=dest_snap_instance))
            self.mock_object(
                self.share_manager.db, 'share_snapshot_instance_update')
            self.mock_object(
                self.share_manager.db,
                'share_snapshot_instance_get_all_with_filters',
                mock.Mock(return_value=[migrating_snap_instance]))
        self.mock_object(self.share_manager.driver, 'migration_start')
        self.mock_object(self.share_manager, '_migration_delete_instance')
        self.mock_object(self.share_manager, 'update_access_for_instances')
        self.mock_object(utils, 'wait_for_access_update')

        # run
        if exc:
            self.assertRaises(
                exception.ShareMigrationFailed,
                self.share_manager._migration_start_driver,
                self.context, share, src_instance, fake_dest_host, False,
                False, False, False, share_network_id, 'fake_az_id',
                'fake_type_id')
        else:
            result = self.share_manager._migration_start_driver(
                self.context, share, src_instance, fake_dest_host, False,
                False, False, False, share_network_id, 'fake_az_id',
                'fake_type_id')

        # asserts
        if not exc:
            self.assertTrue(result)
            self.share_manager.db.share_update.assert_has_calls([
                mock.call(
                    self.context, share['id'],
                    {'task_state':
                     constants.TASK_STATE_MIGRATION_DRIVER_STARTING}),
                mock.call(
                    self.context, share['id'],
                    {'task_state':
                     constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS})
            ])
            (self.share_manager.db.share_instance_update.assert_has_calls([
                mock.call(self.context, migrating_instance['id'],
                          {'status': constants.STATUS_MIGRATING_TO}),
                mock.call(self.context, src_instance['id'],
                          {'cast_rules_to_readonly': True})]))
            (self.share_manager.update_access_for_instances.
             assert_called_once_with(self.context, [src_instance['id']],
                                     share_server_id=src_server['id']))
            self.share_manager.driver.migration_start.assert_called_once_with(
                self.context, src_instance, migrating_instance,
                [snapshot.instance] if has_snapshots else [],
                snapshot_mappings, src_server, dest_server)

        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, migrating_instance['id'], with_share_data=True)
        self.share_manager.db.share_server_get.assert_called_once_with(
            self.context, 'fake_src_server_id')
        (api.API.create_share_instance_and_get_request_spec.
         assert_called_once_with(self.context, share, 'fake_az_id', None,
                                 'fake_host', share_network_id,
                                 'fake_type_id'))
        (self.share_manager.driver.migration_check_compatibility.
         assert_called_once_with(self.context, src_instance,
                                 migrating_instance, src_server, dest_server))

        (self.share_manager.db.share_snapshot_get_all_for_share.
         assert_called_once_with(self.context, share['id']))

        if share_network_id:
            (rpcapi.ShareAPI.provide_share_server.
             assert_called_once_with(
                 self.context, migrating_instance, share_network_id))
            rpcapi.ShareAPI.create_share_server.assert_called_once_with(
                self.context, migrating_instance, 'fake_dest_share_server_id')
            (migration_api.ShareMigrationHelper.wait_for_share_server.
             assert_called_once_with('fake_dest_share_server_id'))
        if exc:
            (self.share_manager._migration_delete_instance.
             assert_called_once_with(self.context, migrating_instance['id']))
            if has_snapshots:
                (self.share_manager.db.share_snapshot_instance_update.
                 assert_called_once_with(
                     self.context, migrating_snap_instance['id'],
                     {'status': constants.STATUS_AVAILABLE}))
                (self.share_manager.db.
                 share_snapshot_instance_get_all_with_filters(
                     self.context,
                     {'share_instance_ids': [src_instance['id']]}))
        else:
            if has_snapshots:
                snap_data = {
                    'status': constants.STATUS_MIGRATING_TO,
                    'progress': '0%',
                    'share_instance_id': migrating_instance['id'],
                }

                (self.share_manager.db.share_snapshot_instance_create.
                 assert_called_once_with(self.context, snapshot['id'],
                                         snap_data))
                (self.share_manager.db.share_snapshot_instance_update.
                 assert_called_once_with(
                     self.context, snapshot.instance['id'],
                     {'status': constants.STATUS_MIGRATING}))

    @ddt.data({'writable': False, 'preserve_metadata': True,
               'nondisruptive': True, 'compatible': True,
               'preserve_snapshots': True, 'has_snapshots': False},
              {'writable': True, 'preserve_metadata': False,
               'nondisruptive': True, 'compatible': True,
               'preserve_snapshots': True, 'has_snapshots': False},
              {'writable': True, 'preserve_metadata': True,
               'nondisruptive': False, 'compatible': True,
               'preserve_snapshots': True, 'has_snapshots': False},
              {'writable': True, 'preserve_metadata': True,
               'nondisruptive': True, 'compatible': False,
               'preserve_snapshots': True, 'has_snapshots': False},
              {'writable': True, 'preserve_metadata': True,
               'nondisruptive': True, 'compatible': True,
               'preserve_snapshots': False, 'has_snapshots': False},
              {'writable': True, 'preserve_metadata': True,
               'nondisruptive': True, 'compatible': True,
               'preserve_snapshots': False, 'has_snapshots': True})
    @ddt.unpack
    def test__migration_start_driver_not_compatible(
            self, compatible, writable, preserve_metadata, nondisruptive,
            preserve_snapshots, has_snapshots):

        share = db_utils.create_share()
        src_instance = db_utils.create_share_instance(
            share_id='fake_id',
            share_server_id='src_server_id',
            share_network_id='fake_share_network_id')
        fake_dest_host = 'fake_host'
        src_server = db_utils.create_share_server()
        dest_server = db_utils.create_share_server()
        migrating_instance = db_utils.create_share_instance(
            share_id='fake_id',
            share_network_id='fake_net_id')
        compatibility = {
            'compatible': compatible,
            'writable': writable,
            'preserve_metadata': preserve_metadata,
            'nondisruptive': nondisruptive,
            'preserve_snapshots': preserve_snapshots,
        }
        snapshot = db_utils.create_snapshot(share_id=share['id'])

        # mocks
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=src_server))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=migrating_instance))
        self.mock_object(
            api.API, 'create_share_instance_and_get_request_spec',
            mock.Mock(return_value=({}, migrating_instance)))
        self.mock_object(rpcapi.ShareAPI, 'provide_share_server',
                         mock.Mock(return_value='fake_dest_share_server_id'))
        self.mock_object(rpcapi.ShareAPI, 'create_share_server')
        self.mock_object(
            migration_api.ShareMigrationHelper, 'wait_for_share_server',
            mock.Mock(return_value=dest_server))
        self.mock_object(self.share_manager.db, 'share_instance_update',
                         mock.Mock(return_value=migrating_instance))
        self.mock_object(self.share_manager, '_migration_delete_instance')
        self.mock_object(self.share_manager.driver,
                         'migration_check_compatibility',
                         mock.Mock(return_value=compatibility))
        self.mock_object(utils, 'wait_for_access_update')
        self.mock_object(
            self.share_manager.db, 'share_snapshot_get_all_for_share',
            mock.Mock(return_value=[snapshot] if has_snapshots else []))

        # run
        self.assertRaises(
            exception.ShareMigrationFailed,
            self.share_manager._migration_start_driver,
            self.context, share, src_instance, fake_dest_host, True, True,
            nondisruptive, not has_snapshots, 'fake_net_id', 'fake_az_id',
            'fake_new_type_id')

        # asserts
        self.share_manager.db.share_server_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), 'src_server_id')
        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, migrating_instance['id'], with_share_data=True)
        if nondisruptive:
            self.share_manager.db.share_instance_update.assert_called_with(
                self.context, migrating_instance['id'],
                {'share_server_id': src_server['id']},
                with_share_data=True
            )
            rpcapi.ShareAPI.provide_share_server.assert_not_called()
            rpcapi.ShareAPI.create_share_server.assert_not_called()
        else:
            (rpcapi.ShareAPI.provide_share_server.
                assert_called_once_with(
                    self.context, migrating_instance, 'fake_net_id'))
            rpcapi.ShareAPI.create_share_server.assert_called_once_with(
                self.context, migrating_instance, 'fake_dest_share_server_id')
            (migration_api.ShareMigrationHelper.wait_for_share_server.
             assert_called_once_with('fake_dest_share_server_id'))

        (api.API.create_share_instance_and_get_request_spec.
         assert_called_once_with(self.context, share, 'fake_az_id', None,
                                 'fake_host', 'fake_net_id',
                                 'fake_new_type_id'))
        self.share_manager._migration_delete_instance.assert_called_once_with(
            self.context, migrating_instance['id'])

    @ddt.data(Exception('fake'), False, True)
    def test_migration_driver_continue(self, finished):

        src_server = db_utils.create_share_server()
        dest_server = db_utils.create_share_server()
        share = db_utils.create_share(
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            id='share_id',
            share_server_id=src_server['id'],
            status=constants.STATUS_MIGRATING)
        share_cancelled = db_utils.create_share(
            task_state=constants.TASK_STATE_MIGRATION_CANCELLED)
        if finished:
            share_cancelled = share
        regular_instance = db_utils.create_share_instance(
            status=constants.STATUS_AVAILABLE,
            share_id='other_id')
        dest_instance = db_utils.create_share_instance(
            share_id='share_id',
            host='fake_host',
            share_server_id=dest_server['id'],
            status=constants.STATUS_MIGRATING_TO)
        src_instance = share.instance
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        dest_snap_instance = db_utils.create_snapshot_instance(
            snapshot_id=snapshot['id'],
            share_instance_id=dest_instance['id'])
        migrating_snap_instance = db_utils.create_snapshot(
            status=constants.STATUS_MIGRATING,
            share_id=share['id'])

        snapshot_mappings = {snapshot.instance['id']: dest_snap_instance}

        self.mock_object(manager.LOG, 'warning')
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_host', mock.Mock(
                             return_value=[regular_instance, src_instance]))
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(side_effect=[share, share_cancelled]))
        self.mock_object(api.API, 'get_migrating_instances',
                         mock.Mock(return_value=(
                             src_instance['id'], dest_instance['id'])))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=dest_instance))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(side_effect=[src_server, dest_server]))
        self.mock_object(self.share_manager.driver, 'migration_continue',
                         mock.Mock(side_effect=[finished]))
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager, '_migration_delete_instance')

        side_effect = [[dest_snap_instance], [snapshot.instance]]
        if isinstance(finished, Exception):
            side_effect.append([migrating_snap_instance])

        self.mock_object(
            self.share_manager.db,
            'share_snapshot_instance_get_all_with_filters',
            mock.Mock(side_effect=side_effect))
        self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')

        share_get_calls = [mock.call(self.context, 'share_id')]
        self.mock_object(self.share_manager, '_reset_read_only_access_rules')

        self.share_manager.migration_driver_continue(self.context)

        snapshot_instance_get_all_calls = [
            mock.call(self.context,
                      {'share_instance_ids': [dest_instance['id']]}),
            mock.call(self.context,
                      {'share_instance_ids': [src_instance['id']]})
        ]

        if isinstance(finished, Exception):
            self.share_manager.db.share_update.assert_called_once_with(
                self.context, 'share_id',
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
            (self.share_manager.db.share_instance_update.
                assert_called_once_with(
                    self.context, src_instance['id'],
                    {'status': constants.STATUS_AVAILABLE}))
            (self.share_manager._migration_delete_instance.
             assert_called_once_with(self.context, dest_instance['id']))
            (self.share_manager._reset_read_only_access_rules.
             assert_called_once_with(self.context, src_instance['id']))
            (self.share_manager.db.share_snapshot_instance_update.
             assert_called_once_with(
                 self.context, migrating_snap_instance['id'],
                 {'status': constants.STATUS_AVAILABLE}))
            snapshot_instance_get_all_calls.append(
                mock.call(
                    self.context,
                    {'share_instance_ids': [src_instance['id']]}))

        else:
            if finished:
                self.share_manager.db.share_update.assert_called_once_with(
                    self.context, 'share_id',
                    {'task_state':
                     constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE})
            else:
                share_get_calls.append(mock.call(self.context, 'share_id'))
                self.assertTrue(manager.LOG.warning.called)

        self.share_manager.db.share_instances_get_all_by_host(
            self.context, self.share_manager.host)
        self.share_manager.db.share_get.assert_has_calls(share_get_calls)
        api.API.get_migrating_instances.assert_called_once_with(share)
        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, dest_instance['id'], with_share_data=True)
        self.share_manager.db.share_server_get.assert_has_calls([
            mock.call(self.context, src_server['id']),
            mock.call(self.context, dest_server['id']),
        ])
        self.share_manager.driver.migration_continue.assert_called_once_with(
            self.context, src_instance, dest_instance,
            [snapshot.instance], snapshot_mappings, src_server, dest_server)

        (self.share_manager.db.share_snapshot_instance_get_all_with_filters.
            assert_has_calls(snapshot_instance_get_all_calls))

    @ddt.data({'task_state': constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
               'exc': None},
              {'task_state': constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
               'exc': Exception('fake')},
              {'task_state': constants.TASK_STATE_DATA_COPYING_COMPLETED,
               'exc': None},
              {'task_state': constants.TASK_STATE_DATA_COPYING_COMPLETED,
               'exc': Exception('fake')})
    @ddt.unpack
    def test_migration_complete(self, task_state, exc):

        instance_1 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING,
            share_server_id='fake_server_id',
            share_type_id='fake_type_id')
        instance_2 = db_utils.create_share_instance(
            share_id='fake_id',
            status=constants.STATUS_MIGRATING_TO,
            share_server_id='fake_server_id',
            share_type_id='fake_type_id')
        share = db_utils.create_share(
            id='fake_id',
            instances=[instance_1, instance_2],
            task_state=task_state)
        model_type_update = {'create_share_from_snapshot_support': False}
        share_update = model_type_update
        share_update['task_state'] = constants.TASK_STATE_MIGRATION_SUCCESS

        # mocks
        self.mock_object(self.share_manager.db, 'share_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instance_1, instance_2]))
        self.mock_object(api.API, 'get_share_attributes_from_share_type',
                         mock.Mock(return_value=model_type_update))
        self.mock_object(share_types, 'get_share_type',
                         mock.Mock(return_value='fake_type'))
        self.mock_object(self.share_manager.db, 'share_update')

        if task_state == constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE:
            self.mock_object(
                self.share_manager, '_migration_complete_driver',
                mock.Mock(side_effect=exc))
        else:
            self.mock_object(
                self.share_manager, '_migration_complete_host_assisted',
                mock.Mock(side_effect=exc))

        if exc:
            snapshot = db_utils.create_snapshot(share_id=share['id'])
            snapshot_ins1 = db_utils.create_snapshot_instance(
                snapshot_id=snapshot['id'],
                share_instance_id=instance_1['id'],
                status=constants.STATUS_MIGRATING,)
            snapshot_ins2 = db_utils.create_snapshot_instance(
                snapshot_id=snapshot['id'],
                share_instance_id=instance_2['id'],
                status=constants.STATUS_MIGRATING_TO)
            self.mock_object(manager.LOG, 'exception')
            self.mock_object(self.share_manager.db, 'share_update')
            self.mock_object(self.share_manager.db, 'share_instance_update')
            self.mock_object(self.share_manager.db,
                             'share_snapshot_instance_update')
            self.mock_object(self.share_manager.db,
                             'share_snapshot_instance_get_all_with_filters',
                             mock.Mock(
                                 return_value=[snapshot_ins1, snapshot_ins2]))

            self.assertRaises(
                exception.ShareMigrationFailed,
                self.share_manager.migration_complete,
                self.context, instance_1['id'], instance_2['id'])

        else:
            self.share_manager.migration_complete(
                self.context, instance_1['id'], instance_2['id'])

        # asserts
        self.share_manager.db.share_get.assert_called_once_with(
            self.context, share['id'])
        self.share_manager.db.share_instance_get.assert_has_calls([
            mock.call(self.context, instance_1['id'], with_share_data=True),
            mock.call(self.context, instance_2['id'], with_share_data=True)])

        if task_state == constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE:
            (self.share_manager._migration_complete_driver.
             assert_called_once_with(
                 self.context, share, instance_1, instance_2))
        else:
            (self.share_manager._migration_complete_host_assisted.
             assert_called_once_with(
                 self.context, share, instance_1['id'], instance_2['id']))
        if exc:
            self.assertTrue(manager.LOG.exception.called)
            self.share_manager.db.share_update.assert_called_once_with(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR})
            if task_state == constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE:
                share_instance_update_calls = [
                    mock.call(self.context, instance_1['id'],
                              {'status': constants.STATUS_ERROR}),
                    mock.call(self.context, instance_2['id'],
                              {'status': constants.STATUS_ERROR})
                ]
            else:
                share_instance_update_calls = [
                    mock.call(self.context, instance_1['id'],
                              {'status': constants.STATUS_AVAILABLE}),
                ]
            self.share_manager.db.share_instance_update.assert_has_calls(
                share_instance_update_calls)
            if task_state == constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE:
                (self.share_manager.db.share_snapshot_instance_update.
                 assert_has_calls([
                     mock.call(self.context, snapshot_ins1['id'],
                               {'status': constants.STATUS_ERROR}),
                     mock.call(self.context, snapshot_ins2['id'],
                               {'status': constants.STATUS_ERROR})]))
                (self.share_manager.db.
                 share_snapshot_instance_get_all_with_filters.
                 assert_called_once_with(
                     self.context, {
                         'share_instance_ids': [instance_1['id'],
                                                instance_2['id']]
                     }
                 ))

        else:
            (api.API.get_share_attributes_from_share_type.
             assert_called_once_with('fake_type'))
            share_types.get_share_type.assert_called_once_with(
                self.context, 'fake_type_id')
            self.share_manager.db.share_update.assert_called_once_with(
                self.context, share['id'], share_update)

    @ddt.data(constants.TASK_STATE_DATA_COPYING_ERROR,
              constants.TASK_STATE_DATA_COPYING_CANCELLED,
              constants.TASK_STATE_DATA_COPYING_COMPLETED,
              'other')
    def test__migration_complete_host_assisted_status(self, status):

        instance = db_utils.create_share_instance(
            share_id='fake_id',
            share_server_id='fake_server_id')
        new_instance = db_utils.create_share_instance(share_id='fake_id')
        share = db_utils.create_share(id='fake_id', task_state=status)
        helper = mock.Mock()

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instance, new_instance]))
        self.mock_object(helper, 'cleanup_new_instance')
        self.mock_object(migration_api, 'ShareMigrationHelper',
                         mock.Mock(return_value=helper))
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager, '_reset_read_only_access_rules')

        if status == constants.TASK_STATE_DATA_COPYING_COMPLETED:
            self.mock_object(helper, 'apply_new_access_rules',
                             mock.Mock(side_effect=Exception('fake')))
            self.mock_object(manager.LOG, 'exception')

        # run
        if status == constants.TASK_STATE_DATA_COPYING_CANCELLED:
            self.share_manager._migration_complete_host_assisted(
                self.context, share, instance['id'], new_instance['id'])
        else:
            self.assertRaises(
                exception.ShareMigrationFailed,
                self.share_manager._migration_complete_host_assisted,
                self.context, share, instance['id'], new_instance['id'])

        # asserts
        self.share_manager.db.share_instance_get.assert_has_calls([
            mock.call(self.context, instance['id'], with_share_data=True),
            mock.call(self.context, new_instance['id'], with_share_data=True)
        ])

        cancelled = not(status == constants.TASK_STATE_DATA_COPYING_CANCELLED)
        if status != 'other':
            helper.cleanup_new_instance.assert_called_once_with(new_instance)
            (self.share_manager._reset_read_only_access_rules.
             assert_called_once_with(self.context, instance['id'],
                                     helper=helper, supress_errors=cancelled))
        if status == constants.TASK_STATE_MIGRATION_CANCELLED:
            (self.share_manager.db.share_instance_update.
                assert_called_once_with(
                    self.context, instance['id'],
                    {'status': constants.STATUS_AVAILABLE,
                     'progress': '100%'}))
            self.share_manager.db.share_update.assert_called_once_with(
                self.context, share['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED})
        if status == constants.TASK_STATE_DATA_COPYING_COMPLETED:
            helper.apply_new_access_rules. assert_called_once_with(
                new_instance, 'fake_id')
            self.assertTrue(manager.LOG.exception.called)

    @ddt.data({'mount_snapshot_support': True, 'snapshot_els': False},
              {'mount_snapshot_support': True, 'snapshot_els': True},
              {'mount_snapshot_support': False, 'snapshot_els': False},
              {'mount_snapshot_support': False, 'snapshot_els': True},)
    @ddt.unpack
    def test__migration_complete_driver(
            self, mount_snapshot_support, snapshot_els):
        fake_src_host = 'src_host'
        fake_dest_host = 'dest_host'
        fake_rules = 'fake_rules'

        src_server = db_utils.create_share_server()
        dest_server = db_utils.create_share_server()
        share_type = db_utils.create_share_type(
            extra_specs={'mount_snapshot_support': mount_snapshot_support})
        share = db_utils.create_share(
            share_server_id='fake_src_server_id',
            host=fake_src_host)
        dest_instance = db_utils.create_share_instance(
            share_id=share['id'],
            share_server_id='fake_dest_server_id',
            host=fake_dest_host,
            share_type_id=share_type['id'])
        src_instance = share.instance
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        dest_snap_instance = db_utils.create_snapshot_instance(
            snapshot_id=snapshot['id'],
            share_instance_id=dest_instance['id'])

        snapshot_mappings = {snapshot.instance['id']: dest_snap_instance}

        model_update = {'fake_keys': 'fake_values'}
        if snapshot_els:
            el = {'path': 'fake_path', 'is_admin_only': False}
            model_update['export_locations'] = [el]

        fake_return_data = {
            'export_locations': 'fake_export_locations',
            'snapshot_updates': {dest_snap_instance['id']: model_update},
        }

        # mocks
        self.mock_object(self.share_manager.db, 'share_server_get', mock.Mock(
            side_effect=[src_server, dest_server]))
        self.mock_object(
            self.share_manager.db, 'share_access_get_all_for_instance',
            mock.Mock(return_value=fake_rules))
        self.mock_object(
            self.share_manager.db, 'share_export_locations_update')
        self.mock_object(self.share_manager.driver, 'migration_complete',
                         mock.Mock(return_value=fake_return_data))
        self.mock_object(
            self.share_manager.access_helper, '_check_needs_refresh',
            mock.Mock(return_value=True))
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager, '_migration_complete_instance')
        self.mock_object(self.share_manager, '_migration_delete_instance')
        self.mock_object(migration_api.ShareMigrationHelper,
                         'apply_new_access_rules')
        self.mock_object(
            share_types,
            'revert_allocated_share_type_quotas_during_migration')
        self.mock_object(
            self.share_manager.db,
            'share_snapshot_instance_get_all_with_filters',
            mock.Mock(side_effect=[[dest_snap_instance],
                                   [snapshot.instance]]))
        self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')
        el_create = self.mock_object(
            self.share_manager.db,
            'share_snapshot_instance_export_location_create')

        # run
        self.share_manager._migration_complete_driver(
            self.context, share, src_instance, dest_instance)

        # asserts
        self.share_manager.db.share_server_get.assert_has_calls([
            mock.call(self.context, 'fake_src_server_id'),
            mock.call(self.context, 'fake_dest_server_id')])
        (self.share_manager.db.share_export_locations_update.
         assert_called_once_with(self.context, dest_instance['id'],
                                 'fake_export_locations'))
        self.share_manager.driver.migration_complete.assert_called_once_with(
            self.context, src_instance, dest_instance, [snapshot.instance],
            snapshot_mappings, src_server, dest_server)
        (migration_api.ShareMigrationHelper.apply_new_access_rules.
         assert_called_once_with(dest_instance, share['id']))
        (self.share_manager._migration_complete_instance.
         assert_called_once_with(self.context, share,
                                 src_instance['id'], dest_instance['id']))
        self.share_manager._migration_delete_instance.assert_called_once_with(
            self.context, src_instance['id'])
        self.share_manager.db.share_update.assert_called_once_with(
            self.context, dest_instance['share_id'],
            {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING})

        (self.share_manager.db.share_snapshot_instance_get_all_with_filters.
         assert_has_calls([
             mock.call(self.context,
                       {'share_instance_ids': [dest_instance['id']]}),
             mock.call(self.context,
                       {'share_instance_ids': [src_instance['id']]})]))

        snap_data_update = (
            fake_return_data['snapshot_updates'][dest_snap_instance['id']])
        snap_data_update.update({
            'status': constants.STATUS_AVAILABLE,
            'progress': '100%',
        })

        (self.share_manager.db.share_snapshot_instance_update.
         assert_called_once_with(self.context, dest_snap_instance['id'],
                                 snap_data_update))
        if mount_snapshot_support and snapshot_els:
            el['share_snapshot_instance_id'] = dest_snap_instance['id']
            el_create.assert_called_once_with(self.context, el)
        else:
            el_create.assert_not_called()
        (share_types.
            revert_allocated_share_type_quotas_during_migration.
            assert_called_once_with(
                self.context, dest_instance, src_instance['share_type_id'],
                allow_deallocate_from_current_type=True))

    def test__migration_complete_host_assisted(self):

        instance = db_utils.create_share_instance(
            share_id='fake_id',
            share_server_id='fake_server_id')
        new_instance = db_utils.create_share_instance(share_id='fake_id')
        share = db_utils.create_share(
            id='fake_id',
            task_state=constants.TASK_STATE_DATA_COPYING_COMPLETED)

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=[instance, new_instance]))
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db, 'share_update')
        self.mock_object(self.share_manager, '_migration_complete_instance')
        delete_mock = self.mock_object(migration_api.ShareMigrationHelper,
                                       'delete_instance_and_wait')
        self.mock_object(migration_api.ShareMigrationHelper,
                         'apply_new_access_rules')

        # run
        self.share_manager._migration_complete_host_assisted(
            self.context, share, instance['id'], new_instance['id'])

        # asserts
        self.share_manager.db.share_instance_get.assert_has_calls([
            mock.call(self.context, instance['id'], with_share_data=True),
            mock.call(self.context, new_instance['id'], with_share_data=True)
        ])

        self.share_manager.db.share_update.assert_called_once_with(
            self.context, share['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING})
        (migration_api.ShareMigrationHelper.apply_new_access_rules.
            assert_called_once_with(new_instance, 'fake_id'))
        delete_mock.assert_called_once_with(instance)
        (self.share_manager._migration_complete_instance.
         assert_called_once_with(self.context, share, instance['id'],
                                 new_instance['id']))

    @ddt.data(constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
              constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
              constants.TASK_STATE_DATA_COPYING_COMPLETED)
    def test_migration_cancel(self, task_state):

        dest_host = 'fake_host'
        server_1 = db_utils.create_share_server()
        server_2 = db_utils.create_share_server()
        share = db_utils.create_share(task_state=task_state)

        instance_1 = db_utils.create_share_instance(
            share_id=share['id'], share_server_id=server_1['id'])
        instance_2 = db_utils.create_share_instance(
            share_id=share['id'], share_server_id=server_2['id'],
            host=dest_host)

        helper = mock.Mock()
        self.mock_object(migration_api, 'ShareMigrationHelper',
                         mock.Mock(return_value=helper))
        self.mock_object(db, 'share_get', mock.Mock(return_value=share))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[instance_1, instance_2]))
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_instance_update')
        self.mock_object(self.share_manager, '_migration_delete_instance')
        self.mock_object(self.share_manager,
                         '_restore_migrating_snapshots_status')
        self.mock_object(db, 'share_server_get',
                         mock.Mock(side_effect=[server_1, server_2]))
        self.mock_object(self.share_manager.driver, 'migration_cancel')
        self.mock_object(helper, 'cleanup_new_instance')
        self.mock_object(self.share_manager, '_reset_read_only_access_rules')
        self.mock_object(
            share_types,
            'revert_allocated_share_type_quotas_during_migration')

        self.share_manager.migration_cancel(
            self.context, instance_1['id'], instance_2['id'])

        share_instance_update_calls = []

        if task_state == constants.TASK_STATE_DATA_COPYING_COMPLETED:
            share_instance_update_calls.append(mock.call(
                self.context, instance_2['id'],
                {'status': constants.STATUS_INACTIVE}))
            (helper.cleanup_new_instance.assert_called_once_with(instance_2))
            (self.share_manager._reset_read_only_access_rules.
             assert_called_once_with(self.context, instance_1['id'],
                                     helper=helper, supress_errors=False))

        else:
            self.share_manager.driver.migration_cancel.assert_called_once_with(
                self.context, instance_1, instance_2, [], {}, server_1,
                server_2)

            (self.share_manager._migration_delete_instance.
             assert_called_once_with(self.context, instance_2['id']))
            (self.share_manager._restore_migrating_snapshots_status.
             assert_called_once_with(self.context, instance_1['id']))

        self.share_manager.db.share_get.assert_called_once_with(
            self.context, share['id'])
        self.share_manager.db.share_server_get.assert_has_calls([
            mock.call(self.context, server_1['id']),
            mock.call(self.context, server_2['id']),
        ])
        self.share_manager.db.share_instance_get.assert_has_calls([
            mock.call(self.context, instance_1['id'], with_share_data=True),
            mock.call(self.context, instance_2['id'], with_share_data=True)
        ])
        self.share_manager.db.share_update.assert_called_once_with(
            self.context, share['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED})

        share_instance_update_calls.append(mock.call(
            self.context, instance_1['id'],
            {'status': constants.STATUS_AVAILABLE}))

        self.share_manager.db.share_instance_update.assert_has_calls(
            share_instance_update_calls)
        (share_types.revert_allocated_share_type_quotas_during_migration.
            assert_called_once_with(
                self.context, instance_1, instance_2['share_type_id']))

    @ddt.data(True, False)
    def test__reset_read_only_access_rules(self, supress_errors):

        share = db_utils.create_share()
        server = db_utils.create_share_server()
        instance = db_utils.create_share_instance(
            share_id=share['id'],
            cast_rules_to_readonly=True,
            share_server_id=server['id'])

        # mocks
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(self.share_manager.db, 'share_instance_update')
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=instance))
        self.mock_object(migration_api.ShareMigrationHelper,
                         'cleanup_access_rules')
        self.mock_object(migration_api.ShareMigrationHelper,
                         'revert_access_rules')

        # run
        self.share_manager._reset_read_only_access_rules(
            self.context, instance['id'], supress_errors=supress_errors)

        # asserts
        self.share_manager.db.share_server_get.assert_called_once_with(
            self.context, server['id'])
        self.share_manager.db.share_instance_update.assert_called_once_with(
            self.context, instance['id'],
            {'cast_rules_to_readonly': False})
        self.share_manager.db.share_instance_get.assert_has_calls([
            mock.call(self.context, instance['id'], with_share_data=True),
            mock.call(self.context, instance['id'], with_share_data=True)])
        if supress_errors:
            (migration_api.ShareMigrationHelper.cleanup_access_rules.
             assert_called_once_with([instance], server, None))
        else:
            (migration_api.ShareMigrationHelper.revert_access_rules.
             assert_called_once_with([instance], server, None))

    def test__migration_delete_instance(self):

        share = db_utils.create_share(id='fake_id')
        instance = share.instance
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        rules = [{'id': 'rule_id_1'}, {'id': 'rule_id_2'}]

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=instance))
        mock_get_access_rules_call = self.mock_object(
            self.share_manager.access_helper,
            'get_and_update_share_instance_access_rules',
            mock.Mock(return_value=rules))
        mock_delete_access_rules_call = self.mock_object(
            self.share_manager.access_helper,
            'delete_share_instance_access_rules')
        self.mock_object(self.share_manager.db, 'share_instance_delete')
        self.mock_object(self.share_manager.db, 'share_instance_access_delete')
        self.mock_object(self.share_manager, '_check_delete_share_server')
        self.mock_object(self.share_manager.db,
                         'share_snapshot_instance_delete')
        self.mock_object(self.share_manager.db,
                         'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=[snapshot.instance]))

        # run
        self.share_manager._migration_delete_instance(
            self.context, instance['id'])

        # asserts
        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, instance['id'], with_share_data=True)
        mock_get_access_rules_call.assert_called_once_with(
            self.context, share_instance_id=instance['id'])
        mock_delete_access_rules_call.assert_called_once_with(
            self.context, rules, instance['id'])
        self.share_manager.db.share_instance_delete.assert_called_once_with(
            self.context, instance['id'])
        self.share_manager._check_delete_share_server.assert_called_once_with(
            self.context, share_instance=instance)
        (self.share_manager.db.share_snapshot_instance_get_all_with_filters.
         assert_called_once_with(self.context,
                                 {'share_instance_ids': [instance['id']]}))
        (self.share_manager.db.share_snapshot_instance_delete.
         assert_called_once_with(self.context, snapshot.instance['id']))

    @ddt.data({}, {'replication_type': 'readable'})
    def test__migration_complete_instance(self, kwargs):
        src_share = db_utils.create_share()
        dest_share = db_utils.create_share(**kwargs)
        src_instance_id = src_share['instance']['id']
        dest_instance_id = dest_share['instance']['id']
        src_updates = {'status': constants.STATUS_INACTIVE}
        dest_updates = dest_updates = {
            'status': constants.STATUS_AVAILABLE,
            'progress': '100%'
        }
        if kwargs.get('replication_type'):
            replication_info = {
                'replica_state': constants.REPLICA_STATE_ACTIVE}
            dest_updates.update(replication_info)

        self.mock_object(self.share_manager.db, 'share_instance_update')

        self.share_manager._migration_complete_instance(
            self.context, dest_share, src_instance_id, dest_instance_id)

        self.share_manager.db.share_instance_update.assert_has_calls(
            [mock.call(self.context, dest_instance_id, dest_updates),
             mock.call(self.context, src_instance_id, src_updates)])

    def test_migration_cancel_invalid(self):

        share = db_utils.create_share()

        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share.instance))
        self.mock_object(db, 'share_get', mock.Mock(return_value=share))

        self.assertRaises(
            exception.InvalidShare, self.share_manager.migration_cancel,
            self.context, 'ins1_id', 'ins2_id')

    def test_migration_get_progress(self):

        expected = 'fake_progress'
        dest_host = 'fake_host'
        server_1 = db_utils.create_share_server()
        server_2 = db_utils.create_share_server()
        share = db_utils.create_share(
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
            share_server_id=server_1['id'])

        instance_1 = db_utils.create_share_instance(
            share_id=share['id'], share_server_id=server_1['id'])
        instance_2 = db_utils.create_share_instance(
            share_id=share['id'], share_server_id=server_2['id'],
            host=dest_host)

        self.mock_object(db, 'share_get', mock.Mock(return_value=share))
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[instance_1, instance_2]))

        self.mock_object(db, 'share_server_get',
                         mock.Mock(side_effect=[server_1, server_2]))

        self.mock_object(self.share_manager.driver, 'migration_get_progress',
                         mock.Mock(return_value=expected))

        result = self.share_manager.migration_get_progress(
            self.context, instance_1['id'], instance_2['id'])

        self.assertEqual(expected, result)

        (self.share_manager.driver.migration_get_progress.
            assert_called_once_with(
                self.context, instance_1, instance_2, [], {}, server_1,
                server_2))

        self.share_manager.db.share_get.assert_called_once_with(
            self.context, share['id'])
        self.share_manager.db.share_server_get.assert_has_calls([
            mock.call(self.context, server_1['id']),
            mock.call(self.context, server_2['id']),
        ])
        self.share_manager.db.share_instance_get.assert_has_calls([
            mock.call(self.context, instance_1['id'], with_share_data=True),
            mock.call(self.context, instance_2['id'], with_share_data=True)
        ])

    def test_migration_get_progress_invalid(self):

        share = db_utils.create_share()

        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share.instance))
        self.mock_object(db, 'share_get', mock.Mock(return_value=share))

        self.assertRaises(
            exception.InvalidShare, self.share_manager.migration_get_progress,
            self.context, 'ins1_id', 'ins2_id')

    def test_provide_share_server(self):

        instance = db_utils.create_share_instance(share_id='fake_id',
                                                  share_group_id='sg_id')
        snapshot = db_utils.create_snapshot(with_share=True)
        group = db_utils.create_share_group()
        server = db_utils.create_share_server()

        # mocks
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=instance))
        self.mock_object(self.share_manager.db, 'share_snapshot_get',
                         mock.Mock(return_value=snapshot))
        self.mock_object(self.share_manager.db, 'share_group_get',
                         mock.Mock(return_value=group))
        self.mock_object(self.share_manager, '_provide_share_server_for_share',
                         mock.Mock(return_value=(server, instance)))

        # run
        result = self.share_manager.provide_share_server(
            self.context, 'ins_id', 'net_id', 'snap_id')

        # asserts
        self.assertEqual(server['id'], result)
        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, 'ins_id', with_share_data=True)
        self.share_manager.db.share_snapshot_get.assert_called_once_with(
            self.context, 'snap_id')
        self.share_manager.db.share_group_get.assert_called_once_with(
            self.context, 'sg_id')
        (self.share_manager._provide_share_server_for_share.
         assert_called_once_with(self.context, 'net_id', instance, snapshot,
                                 group, create_on_backend=False))

    def test_create_share_server(self):

        server = db_utils.create_share_server()
        share = db_utils.create_share()
        fake_metadata = {
            'request_host': 'fake_host',
            'share_type_id': 'fake_share_type_id',
        }

        # mocks
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=server))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(return_value=share))
        self.mock_object(self.share_manager, '_create_share_server_in_backend')
        self.mock_object(self.share_manager, '_build_server_metadata',
                         mock.Mock(return_value=fake_metadata))

        # run
        self.share_manager.create_share_server(
            self.context, 'server_id', 'share_instance_id')

        # asserts
        self.share_manager.db.share_server_get.assert_called_once_with(
            self.context, 'server_id')
        self.share_manager.db.share_instance_get.assert_called_once_with(
            self.context, 'share_instance_id', with_share_data=True)
        (self.share_manager._create_share_server_in_backend.
         assert_called_once_with(self.context, server, fake_metadata))

    @ddt.data({'admin_network_api': mock.Mock(),
               'driver_return': ('new_identifier', {'some_id': 'some_value'})},
              {'admin_network_api': None,
               'driver_return': (None, None)})
    @ddt.unpack
    def test_manage_share_server(self, admin_network_api, driver_return):
        driver_opts = {}
        fake_share_server = fakes.fake_share_server_get()
        fake_list_network_info = [{}, {}]
        fake_list_empty_network_info = []
        identifier = 'fake_id'
        ss_data = {
            'name': 'fake_name',
            'ou': 'fake_ou',
            'domain': 'fake_domain',
            'server': 'fake_server',
            'dns_ip': 'fake_dns_ip',
            'user': 'fake_user',
            'type': 'FAKE',
            'password': 'fake_pass',
        }
        mock_manage_admin_network_allocations = mock.Mock()
        security_service = db_utils.create_security_service(**ss_data)
        share_network = db_utils.create_share_network()
        share_net_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_network['id'])
        fake_share_server['share_network_subnets'] = [share_net_subnet]
        share_server = db_utils.create_share_server(**fake_share_server)
        db.share_network_add_security_service(context.get_admin_context(),
                                              share_network['id'],
                                              security_service['id'])
        share_network = db.share_network_get(context.get_admin_context(),
                                             share_network['id'])
        self.share_manager.driver._admin_network_api = admin_network_api

        mock_share_server_update = self.mock_object(
            db, 'share_server_update')
        mock_share_server_get = self.mock_object(
            db, 'share_server_get', mock.Mock(return_value=share_server))
        mock_share_network_get = self.mock_object(
            db, 'share_network_get', mock.Mock(return_value=share_network))
        mock_share_net_subnet_get = self.mock_object(
            db, 'share_network_subnet_get', mock.Mock(
                return_value=share_net_subnet)
        )
        mock_network_allocations_get = self.mock_object(
            self.share_manager.driver, 'get_network_allocations_number',
            mock.Mock(return_value=1))
        mock_share_server_net_info = self.mock_object(
            self.share_manager.driver, 'get_share_server_network_info',
            mock.Mock(return_value=fake_list_network_info))
        mock_manage_network_allocations = self.mock_object(
            self.share_manager.driver.network_api,
            'manage_network_allocations',
            mock.Mock(return_value=fake_list_empty_network_info))
        mock_manage_server = self.mock_object(
            self.share_manager.driver, 'manage_server',
            mock.Mock(return_value=driver_return))
        mock_set_backend_details = self.mock_object(
            db, 'share_server_backend_details_set')

        ss_from_db = share_network['security_services'][0]
        ss_data_from_db = {
            'name': ss_from_db['name'],
            'ou': ss_from_db['ou'],
            'default_ad_site': ss_from_db['default_ad_site'],
            'domain': ss_from_db['domain'],
            'server': ss_from_db['server'],
            'dns_ip': ss_from_db['dns_ip'],
            'user': ss_from_db['user'],
            'type': ss_from_db['type'],
            'password': ss_from_db['password'],
        }

        expected_backend_details = {
            'security_service_FAKE': jsonutils.dumps(ss_data_from_db),
        }
        if driver_return[1]:
            expected_backend_details.update(driver_return[1])

        if admin_network_api is not None:
            mock_manage_admin_network_allocations = self.mock_object(
                self.share_manager.driver.admin_network_api,
                'manage_network_allocations',
                mock.Mock(return_value=fake_list_network_info))

        self.share_manager.manage_share_server(self.context,
                                               fake_share_server['id'],
                                               identifier,
                                               driver_opts)

        mock_share_server_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id']
        )
        mock_share_network_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_net_subnet['share_network_id']
        )
        mock_share_net_subnet_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_server['share_network_subnet_ids'][0]
        )
        mock_network_allocations_get.assert_called_once_with()
        mock_share_server_net_info.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_server, identifier,
            driver_opts
        )
        mock_manage_network_allocations.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            fake_list_network_info, share_server, share_network,
            share_net_subnet
        )
        mock_manage_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_server, identifier,
            driver_opts
        )
        mock_share_server_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id'],
            {'status': constants.STATUS_ACTIVE,
             'identifier': driver_return[0] or share_server['id'],
             'network_allocation_update_support': False}
        )
        mock_set_backend_details.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_server['id'],
            expected_backend_details
        )
        if admin_network_api is not None:
            mock_manage_admin_network_allocations.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext),
                fake_list_network_info, share_server
            )

    def test_manage_share_server_dhss_false(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self.assertRaises(
            exception.ManageShareServerError,
            self.share_manager.manage_share_server,
            self.context, "fake_id", "foo", {})

    def test_manage_share_server_without_allocations(self):

        driver_opts = {}
        fake_share_server = fakes.fake_share_server_get()
        fake_list_empty_network_info = []
        identifier = 'fake_id'
        share_network = db_utils.create_share_network()
        share_network_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_network['id']
        )
        fake_share_server['share_network_subnets'] = [share_network_subnet]
        share_server = db_utils.create_share_server(**fake_share_server)
        self.share_manager.driver._admin_network_api = mock.Mock()

        mock_share_server_get = self.mock_object(
            db, 'share_server_get', mock.Mock(return_value=share_server))
        mock_share_network_get = self.mock_object(
            db, 'share_network_get', mock.Mock(return_value=share_network))
        mock_share_net_subnet_get = self.mock_object(
            db, 'share_network_subnet_get', mock.Mock(
                return_value=share_network_subnet))
        mock_network_allocations_get = self.mock_object(
            self.share_manager.driver, 'get_network_allocations_number',
            mock.Mock(return_value=1))
        mock_get_share_network_info = self.mock_object(
            self.share_manager.driver, 'get_share_server_network_info',
            mock.Mock(return_value=fake_list_empty_network_info))

        self.assertRaises(exception.ManageShareServerError,
                          self.share_manager.manage_share_server,
                          context=self.context,
                          share_server_id=fake_share_server['id'],
                          identifier=identifier,
                          driver_opts=driver_opts)
        mock_share_server_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id']
        )
        mock_share_network_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_network_subnet['share_network_id']
        )
        mock_share_net_subnet_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_server['share_network_subnet_ids'][0]
        )
        mock_network_allocations_get.assert_called_once_with()
        mock_get_share_network_info.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_server, identifier,
            driver_opts
        )

    def test_manage_share_server_allocations_not_managed(self):
        driver_opts = {}
        fake_share_server = fakes.fake_share_server_get()
        fake_list_network_info = [{}, {}]
        identifier = 'fake_id'
        share_network = db_utils.create_share_network()
        share_network_subnet = db_utils.create_share_network_subnet(
            share_network_id=share_network['id']
        )
        fake_share_server['share_network_subnets'] = [share_network_subnet]
        share_server = db_utils.create_share_server(**fake_share_server)
        self.share_manager.driver._admin_network_api = mock.Mock()

        mock_share_server_get = self.mock_object(
            db, 'share_server_get', mock.Mock(return_value=share_server))
        mock_share_network_get = self.mock_object(
            db, 'share_network_get', mock.Mock(return_value=share_network))
        mock_share_net_subnet_get = self.mock_object(
            db, 'share_network_subnet_get', mock.Mock(
                return_value=share_network_subnet))
        mock_network_allocations_get = self.mock_object(
            self.share_manager.driver, 'get_network_allocations_number',
            mock.Mock(return_value=1))
        mock_get_share_network_info = self.mock_object(
            self.share_manager.driver, 'get_share_server_network_info',
            mock.Mock(return_value=fake_list_network_info))
        mock_manage_admin_network_allocations = self.mock_object(
            self.share_manager.driver.admin_network_api,
            'manage_network_allocations',
            mock.Mock(return_value=fake_list_network_info))
        mock_manage_network_allocations = self.mock_object(
            self.share_manager.driver.network_api,
            'manage_network_allocations',
            mock.Mock(return_value=fake_list_network_info))

        self.assertRaises(exception.ManageShareServerError,
                          self.share_manager.manage_share_server,
                          context=self.context,
                          share_server_id=fake_share_server['id'],
                          identifier=identifier,
                          driver_opts=driver_opts)
        mock_share_server_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id']
        )
        mock_share_network_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_network_subnet['share_network_id']
        )
        mock_share_net_subnet_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            share_server['share_network_subnet_ids'][0]
        )
        mock_network_allocations_get.assert_called_once_with()
        mock_get_share_network_info.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_server, identifier,
            driver_opts
        )
        mock_manage_admin_network_allocations.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            fake_list_network_info, share_server
        )
        mock_manage_network_allocations.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            fake_list_network_info, share_server, share_network,
            share_network_subnet
        )

    def test_manage_snapshot_driver_exception(self):
        CustomException = type('CustomException', (Exception,), {})
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        self.mock_object(share_types,
                         'get_share_type_extra_specs',
                         mock.Mock(return_value="False"))
        mock_manage = self.mock_object(self.share_manager.driver,
                                       'manage_existing_snapshot',
                                       mock.Mock(side_effect=CustomException))
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

    def test_unmanage_share_server_no_allocations(self):

        fake_share_server = fakes.fake_share_server_get()

        ss_list = [
            {'name': 'fake_AD'},
            {'name': 'fake_LDAP'},
            {'name': 'fake_kerberos'}
        ]

        db_utils.create_share_server(**fake_share_server)
        self.mock_object(self.share_manager.driver, 'unmanage_server',
                         mock.Mock(side_effect=NotImplementedError()))
        self.mock_object(self.share_manager.db, 'share_server_delete')

        mock_network_allocations_number = self.mock_object(
            self.share_manager.driver, 'get_network_allocations_number',
            mock.Mock(return_value=0)
        )
        mock_admin_network_allocations_number = self.mock_object(
            self.share_manager.driver, 'get_admin_network_allocations_number',
            mock.Mock(return_value=0)
        )

        self.share_manager.unmanage_share_server(
            self.context, fake_share_server['id'], True)

        mock_network_allocations_number.assert_called_once_with()
        mock_admin_network_allocations_number.assert_called_once_with()

        self.share_manager.driver.unmanage_server.assert_called_once_with(
            fake_share_server['backend_details'], ss_list)
        self.share_manager.db.share_server_delete.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id'])

    def test_unmanage_share_server_no_allocations_driver_not_implemented(self):

        fake_share_server = fakes.fake_share_server_get()
        fake_share_server['status'] = constants.STATUS_UNMANAGING
        ss_list = [
            {'name': 'fake_AD'},
            {'name': 'fake_LDAP'},
            {'name': 'fake_kerberos'}
        ]
        db_utils.create_share_server(**fake_share_server)
        self.mock_object(self.share_manager.driver, 'unmanage_server',
                         mock.Mock(side_effect=NotImplementedError()))
        self.mock_object(self.share_manager.db, 'share_server_update')

        self.share_manager.unmanage_share_server(
            self.context, fake_share_server['id'], False)

        self.share_manager.driver.unmanage_server.assert_called_once_with(
            fake_share_server['backend_details'], ss_list)

        self.share_manager.db.share_server_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id'],
            {'status': constants.STATUS_UNMANAGE_ERROR})

    def test_unmanage_share_server_with_network_allocations(self):

        fake_share_server = fakes.fake_share_server_get()
        db_utils.create_share_server(**fake_share_server)

        mock_unmanage_network_allocations = self.mock_object(
            self.share_manager.driver.network_api,
            'unmanage_network_allocations'
        )
        mock_network_allocations_number = self.mock_object(
            self.share_manager.driver, 'get_network_allocations_number',
            mock.Mock(return_value=1)
        )

        self.share_manager.unmanage_share_server(
            self.context, fake_share_server['id'], True)
        mock_network_allocations_number.assert_called_once_with()
        mock_unmanage_network_allocations.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id'])

    def test_unmanage_share_server_with_admin_network_allocations(self):

        fake_share_server = fakes.fake_share_server_get()
        db_utils.create_share_server(**fake_share_server)

        mock_admin_network_allocations_number = self.mock_object(
            self.share_manager.driver, 'get_admin_network_allocations_number',
            mock.Mock(return_value=1)
        )
        mock_network_allocations_number = self.mock_object(
            self.share_manager.driver, 'get_network_allocations_number',
            mock.Mock(return_value=0)
        )

        self.share_manager.driver._admin_network_api = mock.Mock()
        self.share_manager.unmanage_share_server(
            self.context, fake_share_server['id'], True)

        mock_admin_network_allocations_number.assert_called_once_with()
        mock_network_allocations_number.assert_called_once_with()

    def test_unmanage_share_server_error(self):

        fake_share_server = fakes.fake_share_server_get()
        db_utils.create_share_server(**fake_share_server)

        mock_network_allocations_number = self.mock_object(
            self.share_manager.driver, 'get_network_allocations_number',
            mock.Mock(return_value=1)
        )
        error = mock.Mock(
            side_effect=exception.ShareServerNotFound(share_server_id="fake"))

        mock_share_server_delete = self.mock_object(
            db, 'share_server_delete', error
        )
        mock_share_server_update = self.mock_object(
            db, 'share_server_update'
        )
        self.share_manager.driver._admin_network_api = mock.Mock()

        self.assertRaises(exception.ShareServerNotFound,
                          self.share_manager.unmanage_share_server,
                          self.context,
                          fake_share_server['id'],
                          True)
        mock_network_allocations_number.assert_called_once_with()
        mock_share_server_delete.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id']
        )
        mock_share_server_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id'],
            {'status': constants.STATUS_UNMANAGE_ERROR}
        )

    def test_unmanage_share_server_network_allocations_error(self):

        fake_share_server = fakes.fake_share_server_get()
        db_utils.create_share_server(**fake_share_server)

        mock_network_allocations_number = self.mock_object(
            self.share_manager.driver, 'get_network_allocations_number',
            mock.Mock(return_value=1)
        )
        error = mock.Mock(
            side_effect=exception.ShareNetworkNotFound(share_network_id="fake")
        )
        mock_unmanage_network_allocations = self.mock_object(
            self.share_manager.driver.network_api,
            'unmanage_network_allocations', error)

        mock_share_server_update = self.mock_object(
            db, 'share_server_update'
        )
        self.share_manager.driver._admin_network_api = mock.Mock()

        self.assertRaises(exception.ShareNetworkNotFound,
                          self.share_manager.unmanage_share_server,
                          self.context,
                          fake_share_server['id'],
                          True)

        mock_network_allocations_number.assert_called_once_with()
        mock_unmanage_network_allocations.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id']
        )
        mock_share_server_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id'],
            {'status': constants.STATUS_UNMANAGE_ERROR}
        )

    def test_unmanage_share_server_admin_network_allocations_error(self):

        fake_share_server = fakes.fake_share_server_get()
        db_utils.create_share_server(**fake_share_server)
        self.share_manager.driver._admin_network_api = mock.Mock()

        mock_network_allocations_number = self.mock_object(
            self.share_manager.driver, 'get_network_allocations_number',
            mock.Mock(return_value=0)
        )
        mock_admin_network_allocations_number = self.mock_object(
            self.share_manager.driver, 'get_admin_network_allocations_number',
            mock.Mock(return_value=1)
        )
        error = mock.Mock(
            side_effect=exception.ShareNetworkNotFound(share_network_id="fake")
        )
        mock_unmanage_admin_network_allocations = self.mock_object(
            self.share_manager.driver._admin_network_api,
            'unmanage_network_allocations', error
        )
        mock_unmanage_network_allocations = self.mock_object(
            self.share_manager.driver.network_api,
            'unmanage_network_allocations', error)

        mock_share_server_update = self.mock_object(
            db, 'share_server_update'
        )

        self.assertRaises(exception.ShareNetworkNotFound,
                          self.share_manager.unmanage_share_server,
                          self.context,
                          fake_share_server['id'],
                          True)
        mock_network_allocations_number.assert_called_once_with()
        mock_admin_network_allocations_number.assert_called_once_with()
        mock_unmanage_network_allocations.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id']
        )
        mock_unmanage_admin_network_allocations.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id']
        )
        mock_share_server_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), fake_share_server['id'],
            {'status': constants.STATUS_UNMANAGE_ERROR}
        )

    @ddt.data({'dhss': True, 'driver_data': {'size': 1},
               'mount_snapshot_support': False},
              {'dhss': True, 'driver_data': {'size': 2, 'name': 'fake'},
               'mount_snapshot_support': False},
              {'dhss': False, 'driver_data': {'size': 3},
               'mount_snapshot_support': False},
              {'dhss': False, 'driver_data': {'size': 3, 'export_locations': [
                  {'path': '/path1', 'is_admin_only': True},
                  {'path': '/path2', 'is_admin_only': False}
              ]}, 'mount_snapshot_support': False},
              {'dhss': False, 'driver_data': {'size': 3, 'export_locations': [
                  {'path': '/path1', 'is_admin_only': True},
                  {'path': '/path2', 'is_admin_only': False}
              ]}, 'mount_snapshot_support': True})
    @ddt.unpack
    def test_manage_snapshot_valid_snapshot(
            self, driver_data, mount_snapshot_support, dhss):
        mock_get_share_server = self.mock_object(self.share_manager,
                                                 '_get_share_server',
                                                 mock.Mock(return_value=None))
        self.mock_object(self.share_manager.db, 'share_snapshot_update')
        self.mock_object(self.share_manager, 'driver')
        self.mock_object(quota.QUOTAS, 'reserve', mock.Mock())
        self.share_manager.driver.driver_handles_share_servers = dhss

        if dhss:
            mock_manage = self.mock_object(
                self.share_manager.driver,
                "manage_existing_snapshot_with_server",
                mock.Mock(return_value=driver_data))
        else:
            mock_manage = self.mock_object(
                self.share_manager.driver,
                "manage_existing_snapshot",
                mock.Mock(return_value=driver_data))
        size = driver_data['size']
        export_locations = driver_data.get('export_locations')
        share = db_utils.create_share(
            size=size,
            mount_snapshot_support=mount_snapshot_support)
        snapshot = db_utils.create_snapshot(share_id=share['id'], size=size)
        snapshot_id = snapshot['id']
        driver_options = {}
        mock_get = self.mock_object(self.share_manager.db,
                                    'share_snapshot_get',
                                    mock.Mock(return_value=snapshot))
        mock_export_update = self.mock_object(
            self.share_manager.db,
            'share_snapshot_instance_export_location_create')

        self.share_manager.manage_snapshot(self.context, snapshot_id,
                                           driver_options)

        if dhss:
            mock_manage.assert_called_once_with(mock.ANY, driver_options, None)
        else:
            mock_manage.assert_called_once_with(mock.ANY, driver_options)
        valid_snapshot_data = {
            'status': constants.STATUS_AVAILABLE}
        valid_snapshot_data.update(driver_data)
        self.share_manager.db.share_snapshot_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            snapshot_id, valid_snapshot_data)
        if dhss:
            mock_get_share_server.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext), snapshot['share'])
        mock_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot_id)
        if mount_snapshot_support and export_locations:
            snap_ins_id = snapshot.instance['id']
            for i in range(0, 2):
                export_locations[i]['share_snapshot_instance_id'] = snap_ins_id
            mock_export_update.assert_has_calls([
                mock.call(utils.IsAMatcher(context.RequestContext),
                          export_locations[0]),
                mock.call(utils.IsAMatcher(context.RequestContext),
                          export_locations[1]),
            ])
        else:
            mock_export_update.assert_not_called()

    def test_unmanage_snapshot_invalid_share(self):
        manager.CONF.unmanage_remove_access_rules = False
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

    @ddt.data({'dhss': False, 'quota_error': False},
              {'dhss': True, 'quota_error': False},
              {'dhss': False, 'quota_error': True},
              {'dhss': True, 'quota_error': True})
    @ddt.unpack
    def test_unmanage_snapshot_valid_snapshot(self, dhss, quota_error):
        if quota_error:
            self.mock_object(quota.QUOTAS, 'reserve', mock.Mock(
                side_effect=exception.ManilaException(message='error')))
        manager.CONF.unmanage_remove_access_rules = True
        mock_log_warning = self.mock_object(manager.LOG, 'warning')
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = dhss
        mock_update_access = self.mock_object(
            self.share_manager.snapshot_access_helper, "update_access_rules")
        if dhss:
            mock_unmanage = self.mock_object(
                self.share_manager.driver, "unmanage_snapshot_with_server")
        else:
            mock_unmanage = self.mock_object(
                self.share_manager.driver, "unmanage_snapshot")
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
        mock_snap_ins_get = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_get',
            mock.Mock(return_value=snapshot.instance))

        self.share_manager.unmanage_snapshot(self.context, snapshot['id'])

        if dhss:
            mock_unmanage.assert_called_once_with(snapshot.instance, None)
        else:
            mock_unmanage.assert_called_once_with(snapshot.instance)
        mock_update_access.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot.instance['id'],
            delete_all_rules=True, share_server=None)
        mock_snapshot_instance_destroy_call.assert_called_once_with(
            mock.ANY, snapshot['instance']['id'])
        mock_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        mock_get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['share'])
        mock_snap_ins_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot.instance['id'],
            with_share_data=True)
        if quota_error:
            self.assertTrue(mock_log_warning.called)

    @ddt.data(True, False)
    def test_revert_to_snapshot(self, has_replicas):

        reservations = 'fake_reservations'
        share_id = 'fake_share_id'
        snapshot_id = 'fake_snapshot_id'
        snapshot_instance_id = 'fake_snapshot_instance_id'
        share_instance_id = 'fake_share_instance_id'
        share_instance = fakes.fake_share_instance(
            id=share_instance_id, share_id=share_id)
        share = fakes.fake_share(
            id=share_id, instance=share_instance,
            project_id='fake_project', user_id='fake_user', size=2,
            has_replicas=has_replicas)
        snapshot_instance = fakes.fake_snapshot_instance(
            id=snapshot_instance_id, share_id=share_instance_id, share=share,
            name='fake_snapshot', share_instance=share_instance,
            share_instance_id=share_instance_id)
        snapshot = fakes.fake_snapshot(
            id=snapshot_id, share_id=share_id, share=share,
            instance=snapshot_instance, project_id='fake_project',
            user_id='fake_user', size=1)
        share_access_rules = ['fake_share_access_rule']
        snapshot_access_rules = ['fake_snapshot_access_rule']

        mock_share_snapshot_get = self.mock_object(
            self.share_manager.db, 'share_snapshot_get',
            mock.Mock(return_value=snapshot))
        mock_share_access_get = self.mock_object(
            self.share_manager.access_helper,
            'get_share_instance_access_rules',
            mock.Mock(return_value=share_access_rules))
        mock_snapshot_access_get = self.mock_object(
            self.share_manager.snapshot_access_helper,
            'get_snapshot_instance_access_rules',
            mock.Mock(return_value=snapshot_access_rules))
        mock_revert_to_snapshot = self.mock_object(
            self.share_manager, '_revert_to_snapshot')
        mock_revert_to_replicated_snapshot = self.mock_object(
            self.share_manager, '_revert_to_replicated_snapshot')

        self.share_manager.revert_to_snapshot(self.context, snapshot_id,
                                              reservations)

        mock_share_snapshot_get.assert_called_once_with(mock.ANY, snapshot_id)
        mock_share_access_get.assert_called_once_with(
            mock.ANY, filters={'state': constants.STATUS_ACTIVE},
            share_instance_id=share_instance_id)
        mock_snapshot_access_get.assert_called_once_with(
            mock.ANY, snapshot_instance_id)

        if not has_replicas:
            mock_revert_to_snapshot.assert_called_once_with(
                mock.ANY, share, snapshot, reservations, share_access_rules,
                snapshot_access_rules)
            self.assertFalse(mock_revert_to_replicated_snapshot.called)
        else:
            self.assertFalse(mock_revert_to_snapshot.called)
            mock_revert_to_replicated_snapshot.assert_called_once_with(
                mock.ANY, share, snapshot, reservations, share_access_rules,
                snapshot_access_rules, share_id=share_id)

    @ddt.data(None, 'fake_reservations')
    def test__revert_to_snapshot(self, reservations):

        mock_quotas_rollback = self.mock_object(quota.QUOTAS, 'rollback')
        mock_quotas_commit = self.mock_object(quota.QUOTAS, 'commit')
        self.mock_object(
            self.share_manager, '_get_share_server',
            mock.Mock(return_value=None))
        mock_driver = self.mock_object(self.share_manager, 'driver')

        share_id = 'fake_share_id'
        share = fakes.fake_share(
            id=share_id, instance={'id': 'fake_instance_id',
                                   'share_type_id': 'fake_share_type_id'},
            project_id='fake_project', user_id='fake_user', size=2)
        snapshot_instance = fakes.fake_snapshot_instance(
            share_id=share_id, share=share, name='fake_snapshot',
            share_instance=share['instance'])
        snapshot = fakes.fake_snapshot(
            id='fake_snapshot_id', share_id=share_id, share=share,
            instance=snapshot_instance, project_id='fake_project',
            user_id='fake_user', size=1)
        share_access_rules = []
        snapshot_access_rules = []

        self.mock_object(
            self.share_manager.db, 'share_snapshot_get',
            mock.Mock(return_value=snapshot))
        self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_get',
            mock.Mock(return_value=snapshot_instance))
        mock_share_update = self.mock_object(
            self.share_manager.db, 'share_update')
        mock_share_snapshot_update = self.mock_object(
            self.share_manager.db, 'share_snapshot_update')

        self.share_manager._revert_to_snapshot(self.context, share, snapshot,
                                               reservations,
                                               share_access_rules,
                                               snapshot_access_rules)

        mock_driver.revert_to_snapshot.assert_called_once_with(
            mock.ANY,
            self._get_snapshot_instance_dict(
                snapshot_instance, share, snapshot=snapshot),
            share_access_rules, snapshot_access_rules,
            share_server=None)

        self.assertFalse(mock_quotas_rollback.called)
        if reservations:
            mock_quotas_commit.assert_called_once_with(
                mock.ANY, reservations, project_id='fake_project',
                user_id='fake_user',
                share_type_id=(
                    snapshot_instance['share_instance']['share_type_id']))
        else:
            self.assertFalse(mock_quotas_commit.called)

        mock_share_update.assert_called_once_with(
            mock.ANY, share_id,
            {'status': constants.STATUS_AVAILABLE, 'size': snapshot['size']})
        mock_share_snapshot_update.assert_called_once_with(
            mock.ANY, 'fake_snapshot_id',
            {'status': constants.STATUS_AVAILABLE})

    @ddt.data(None, 'fake_reservations')
    def test__revert_to_snapshot_driver_exception(self, reservations):

        mock_quotas_rollback = self.mock_object(quota.QUOTAS, 'rollback')
        mock_quotas_commit = self.mock_object(quota.QUOTAS, 'commit')
        self.mock_object(
            self.share_manager, '_get_share_server',
            mock.Mock(return_value=None))
        mock_driver = self.mock_object(self.share_manager, 'driver')
        mock_driver.revert_to_snapshot.side_effect = exception.ManilaException

        share_id = 'fake_share_id'
        share = fakes.fake_share(
            id=share_id, instance={'id': 'fake_instance_id',
                                   'share_type_id': 'fake_share_type_id'},
            project_id='fake_project', user_id='fake_user', size=2)
        snapshot_instance = fakes.fake_snapshot_instance(
            share_id=share_id, share=share, name='fake_snapshot',
            share_instance=share['instance'])
        snapshot = fakes.fake_snapshot(
            id='fake_snapshot_id', share_id=share_id, share=share,
            instance=snapshot_instance, project_id='fake_project',
            user_id='fake_user', size=1)
        share_access_rules = []
        snapshot_access_rules = []

        self.mock_object(
            self.share_manager.db, 'share_snapshot_get',
            mock.Mock(return_value=snapshot))
        self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_get',
            mock.Mock(return_value=snapshot_instance))
        mock_share_update = self.mock_object(
            self.share_manager.db, 'share_update')
        mock_share_snapshot_update = self.mock_object(
            self.share_manager.db, 'share_snapshot_update')

        self.assertRaises(exception.ManilaException,
                          self.share_manager._revert_to_snapshot,
                          self.context,
                          share,
                          snapshot,
                          reservations,
                          share_access_rules,
                          snapshot_access_rules)

        mock_driver.revert_to_snapshot.assert_called_once_with(
            mock.ANY,
            self._get_snapshot_instance_dict(
                snapshot_instance, share, snapshot=snapshot),
            share_access_rules,
            snapshot_access_rules,
            share_server=None)

        self.assertFalse(mock_quotas_commit.called)
        if reservations:
            mock_quotas_rollback.assert_called_once_with(
                mock.ANY, reservations, project_id='fake_project',
                user_id='fake_user',
                share_type_id=(
                    snapshot_instance['share_instance']['share_type_id']))
        else:
            self.assertFalse(mock_quotas_rollback.called)

        mock_share_update.assert_called_once_with(
            mock.ANY, share_id,
            {'status': constants.STATUS_REVERTING_ERROR})
        mock_share_snapshot_update.assert_called_once_with(
            mock.ANY, 'fake_snapshot_id',
            {'status': constants.STATUS_AVAILABLE})

    def test_unmanage_snapshot_update_access_rule_exception(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        share = db_utils.create_share()
        snapshot = db_utils.create_snapshot(share_id=share['id'])
        manager.CONF.unmanage_remove_access_rules = True

        mock_get = self.mock_object(
            self.share_manager.db, 'share_snapshot_get',
            mock.Mock(return_value=snapshot))

        mock_get_share_server = self.mock_object(
            self.share_manager, '_get_share_server',
            mock.Mock(return_value=None))

        self.mock_object(self.share_manager.snapshot_access_helper,
                         'update_access_rules',
                         mock.Mock(side_effect=Exception))
        mock_log_exception = self.mock_object(manager.LOG, 'exception')

        mock_update = self.mock_object(self.share_manager.db,
                                       'share_snapshot_update')

        self.share_manager.unmanage_snapshot(self.context, snapshot['id'])

        self.assertTrue(mock_log_exception.called)
        mock_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        mock_get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['share'])
        mock_update.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'],
            {'status': constants.STATUS_UNMANAGE_ERROR})

    def test_snapshot_update_access(self):
        snapshot = fakes.fake_snapshot(create_instance=True)
        snapshot_instance = fakes.fake_snapshot_instance(
            base_snapshot=snapshot)

        mock_instance_get = self.mock_object(
            db, 'share_snapshot_instance_get',
            mock.Mock(return_value=snapshot_instance))

        mock_get_share_server = self.mock_object(self.share_manager,
                                                 '_get_share_server',
                                                 mock.Mock(return_value=None))

        mock_update_access = self.mock_object(
            self.share_manager.snapshot_access_helper, 'update_access_rules')

        self.share_manager.snapshot_update_access(self.context,
                                                  snapshot_instance['id'])

        mock_instance_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            snapshot_instance['id'], with_share_data=True)
        mock_get_share_server.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            snapshot_instance['share_instance'])
        mock_update_access.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            snapshot_instance['id'], share_server=None)

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

    @ddt.data(None, 'fake_reservations')
    def test_revert_to_replicated_snapshot(self, reservations):

        share_id = 'id1'
        mock_quotas_rollback = self.mock_object(quota.QUOTAS, 'rollback')
        mock_quotas_commit = self.mock_object(quota.QUOTAS, 'commit')
        share = fakes.fake_share(
            id=share_id, project_id='fake_project', user_id='fake_user')
        snapshot = fakes.fake_snapshot(
            create_instance=True, share=share, size=1)
        snapshot_instance = fakes.fake_snapshot_instance(
            base_snapshot=snapshot)
        snapshot_instances = [snapshot['instance'], snapshot_instance]
        active_replica = fake_replica(
            id='rid1', share_id=share_id, host=self.share_manager.host,
            replica_state=constants.REPLICA_STATE_ACTIVE, as_primitive=False)
        replica = fake_replica(
            id='rid2', share_id=share_id, host='secondary',
            replica_state=constants.REPLICA_STATE_IN_SYNC, as_primitive=False)
        replicas = [active_replica, replica]
        share_access_rules = []
        snapshot_access_rules = []
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(
            self.share_manager, '_get_share_server',
            mock.Mock(return_value=None))
        self.mock_object(
            db, 'share_replicas_get_all_by_share',
            mock.Mock(return_value=replicas))
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(side_effect=[snapshot_instances,
                                   [snapshot_instances[0]]]))
        mock_driver = self.mock_object(self.share_manager, 'driver')
        mock_share_update = self.mock_object(
            self.share_manager.db, 'share_update')
        mock_share_replica_update = self.mock_object(
            self.share_manager.db, 'share_replica_update')
        mock_share_snapshot_instance_update = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')

        self.share_manager._revert_to_replicated_snapshot(
            self.context, share, snapshot, reservations, share_access_rules,
            snapshot_access_rules, share_id=share_id)

        self.assertTrue(mock_driver.revert_to_replicated_snapshot.called)
        self.assertFalse(mock_quotas_rollback.called)
        if reservations:
            mock_quotas_commit.assert_called_once_with(
                mock.ANY, reservations, project_id='fake_project',
                user_id='fake_user', share_type_id=None)
        else:
            self.assertFalse(mock_quotas_commit.called)

        mock_share_update.assert_called_once_with(
            mock.ANY, share_id, {'size': snapshot['size']})
        mock_share_replica_update.assert_called_once_with(
            mock.ANY, active_replica['id'],
            {'status': constants.STATUS_AVAILABLE})
        mock_share_snapshot_instance_update.assert_called_once_with(
            mock.ANY, snapshot['instance']['id'],
            {'status': constants.STATUS_AVAILABLE})

    @ddt.data(None, 'fake_reservations')
    def test_revert_to_replicated_snapshot_driver_exception(
            self, reservations):

        mock_quotas_rollback = self.mock_object(quota.QUOTAS, 'rollback')
        mock_quotas_commit = self.mock_object(quota.QUOTAS, 'commit')
        share_id = 'id1'
        share = fakes.fake_share(
            id=share_id, project_id='fake_project', user_id='fake_user')
        snapshot = fakes.fake_snapshot(
            create_instance=True, share=share, size=1)
        snapshot_instance = fakes.fake_snapshot_instance(
            base_snapshot=snapshot)
        snapshot_instances = [snapshot['instance'], snapshot_instance]
        active_replica = fake_replica(
            id='rid1', share_id=share_id, host=self.share_manager.host,
            replica_state=constants.REPLICA_STATE_ACTIVE, as_primitive=False,
            share_type_id='fake_share_type_id')
        replica = fake_replica(
            id='rid2', share_id=share_id, host='secondary',
            replica_state=constants.REPLICA_STATE_IN_SYNC, as_primitive=False,
            share_type_id='fake_share_type_id')
        replicas = [active_replica, replica]
        share_access_rules = []
        snapshot_access_rules = []
        self.mock_object(
            db, 'share_snapshot_get', mock.Mock(return_value=snapshot))
        self.mock_object(
            self.share_manager, '_get_share_server',
            mock.Mock(return_value=None))
        self.mock_object(
            db, 'share_replicas_get_all_by_share',
            mock.Mock(return_value=replicas))
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(side_effect=[snapshot_instances,
                                   [snapshot_instances[0]]]))
        mock_driver = self.mock_object(self.share_manager, 'driver')
        mock_driver.revert_to_replicated_snapshot.side_effect = (
            exception.ManilaException)
        mock_share_update = self.mock_object(
            self.share_manager.db, 'share_update')
        mock_share_replica_update = self.mock_object(
            self.share_manager.db, 'share_replica_update')
        mock_share_snapshot_instance_update = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')

        self.assertRaises(exception.ManilaException,
                          self.share_manager._revert_to_replicated_snapshot,
                          self.context,
                          share,
                          snapshot,
                          reservations,
                          share_access_rules,
                          snapshot_access_rules,
                          share_id=share_id)

        self.assertTrue(mock_driver.revert_to_replicated_snapshot.called)
        self.assertFalse(mock_quotas_commit.called)
        if reservations:
            mock_quotas_rollback.assert_called_once_with(
                mock.ANY, reservations, project_id='fake_project',
                user_id='fake_user', share_type_id=replica['share_type_id'])
        else:
            self.assertFalse(mock_quotas_rollback.called)

        self.assertFalse(mock_share_update.called)
        mock_share_replica_update.assert_called_once_with(
            mock.ANY, active_replica['id'],
            {'status': constants.STATUS_REVERTING_ERROR})
        mock_share_snapshot_instance_update.assert_called_once_with(
            mock.ANY, snapshot['instance']['id'],
            {'status': constants.STATUS_AVAILABLE})

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
            self.assertEqual(2, mock_db_delete_call.call_count)
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

    def test_update_access(self):
        share_server = fakes.fake_share_server_get()
        kwargs = {'share_server_id': share_server['id']}
        share_instance = fakes.fake_share_instance(**kwargs)
        self.mock_object(self.share_manager, '_get_share_server',
                         mock.Mock(return_value='fake_share_server'))
        self.mock_object(self.share_manager, '_get_share_instance',
                         mock.Mock(return_value=share_instance))
        self.mock_object(self.share_manager.db, 'share_server_get',
                         mock.Mock(return_value=share_server))
        access_rules_update_method = self.mock_object(
            self.share_manager.access_helper, 'update_access_rules')

        retval = self.share_manager.update_access(
            self.context, share_instance['id'])

        self.assertIsNone(retval)
        access_rules_update_method.assert_called_once_with(
            self.context, share_instance['id'],
            share_server=share_server)

    @mock.patch('manila.tests.fake_notifier.FakeNotifier._notify')
    def test_update_share_usage_size(self, mock_notify):
        instances = self._setup_init_mocks(setup_access_rules=False)
        update_shares = [{'id': 'fake_id', 'used_size': '3',
                          'gathered_at': 'fake'}]
        mock_notify.assert_not_called()

        manager = self.share_manager
        self.mock_object(manager, 'driver')
        self.mock_object(manager.db, 'share_instances_get_all_by_host',
                         mock.Mock(return_value=instances))
        self.mock_object(manager.db, 'share_instance_get',
                         mock.Mock(side_effect=instances))
        mock_driver_call = self.mock_object(
            manager.driver, 'update_share_usage_size',
            mock.Mock(return_value=update_shares))
        self.share_manager.update_share_usage_size(self.context)
        self.assert_notify_called(mock_notify,
                                  (['INFO', 'share.consumed.size'], ))
        mock_driver_call.assert_called_once_with(
            self.context, instances)

    @mock.patch('manila.tests.fake_notifier.FakeNotifier._notify')
    def test_update_share_usage_size_fail(self, mock_notify):
        instances = self._setup_init_mocks(setup_access_rules=False)
        mock_notify.assert_not_called()

        self.mock_object(self.share_manager, 'driver')
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_host',
                         mock.Mock(return_value=instances))
        self.mock_object(self.share_manager.db, 'share_instance_get',
                         mock.Mock(side_effect=instances))
        self.mock_object(
            self.share_manager.driver, 'update_share_usage_size',
            mock.Mock(side_effect=exception.ProcessExecutionError))
        mock_log_exception = self.mock_object(manager.LOG, 'exception')
        self.share_manager.update_share_usage_size(self.context)
        self.assertTrue(mock_log_exception.called)

    def test_periodic_share_status_update(self):
        instances = self._setup_init_mocks(setup_access_rules=False)
        instances_creating_from_snap = [
            x for x in instances
            if x['status'] == constants.STATUS_CREATING_FROM_SNAPSHOT
        ]
        self.mock_object(self.share_manager, 'driver')
        self.mock_object(self.share_manager.db,
                         'share_instances_get_all_by_host',
                         mock.Mock(return_value=instances_creating_from_snap))
        mock_update_share_status = self.mock_object(
            self.share_manager, '_update_share_status')
        instances_dict = [
            self.share_manager._get_share_instance_dict(self.context, si)
            for si in instances_creating_from_snap]

        self.share_manager.periodic_share_status_update(self.context)
        mock_update_share_status.assert_has_calls([
            mock.call(self.context, share_instance)
            for share_instance in instances_dict
        ])

    def test__update_share_status(self):
        instances = self._setup_init_mocks(setup_access_rules=False)
        fake_export_locations = ['fake/path/1', 'fake/path']
        instance_model_update = {
            'status': constants.STATUS_AVAILABLE,
            'export_locations': fake_export_locations
        }
        expected_si_update_info = {
            'status': constants.STATUS_AVAILABLE,
            'progress': '100%'
        }
        driver_get_status = self.mock_object(
            self.share_manager.driver, 'get_share_status',
            mock.Mock(return_value=instance_model_update))
        db_si_update = self.mock_object(self.share_manager.db,
                                        'share_instance_update')
        db_el_update = self.mock_object(self.share_manager.db,
                                        'share_export_locations_update')

        in_progress_instances = [x for x in instances
                                 if x['status'] ==
                                 constants.STATUS_CREATING_FROM_SNAPSHOT]
        instance = self.share_manager.db.share_instance_get(
            self.context, in_progress_instances[0]['id'], with_share_data=True)
        self.share_manager._update_share_status(self.context, instance)

        driver_get_status.assert_called_once_with(instance, None)
        db_si_update.assert_called_once_with(self.context, instance['id'],
                                             expected_si_update_info)
        db_el_update.assert_called_once_with(self.context, instance['id'],
                                             fake_export_locations)

    @ddt.data(mock.Mock(return_value={'status': constants.STATUS_ERROR}),
              mock.Mock(side_effect=exception.ShareBackendException(
                  msg='fake_msg')))
    def test__update_share_status_share_with_error_or_exception(self,
                                                                driver_error):
        instances = self._setup_init_mocks(setup_access_rules=False)
        expected_si_update_info = {
            'status': constants.STATUS_ERROR,
            'progress': None,
        }
        driver_get_status = self.mock_object(
            self.share_manager.driver, 'get_share_status', driver_error)
        db_si_update = self.mock_object(self.share_manager.db,
                                        'share_instance_update')

        in_progress_instances = [x for x in instances
                                 if x['status'] ==
                                 constants.STATUS_CREATING_FROM_SNAPSHOT]
        instance = self.share_manager.db.share_instance_get(
            self.context, in_progress_instances[0]['id'], with_share_data=True)

        self.share_manager._update_share_status(self.context, instance)
        driver_get_status.assert_called_once_with(instance, None)
        db_si_update.assert_called_once_with(self.context, instance['id'],
                                             expected_si_update_info)
        self.share_manager.message_api.create.assert_called_once_with(
            self.context,
            message_field.Action.UPDATE,
            instance['project_id'],
            resource_type=message_field.Resource.SHARE,
            resource_id=instance['share_id'],
            detail=message_field.Detail.DRIVER_FAILED_CREATING_FROM_SNAP)

    def test__build_server_metadata(self):
        share = {'host': 'host', 'share_type_id': 'id'}
        expected_metadata = {'request_host': 'host', 'share_type_id': 'id'}

        metadata = self.share_manager._build_server_metadata(
            share['host'], share['share_type_id'])

        self.assertDictEqual(expected_metadata, metadata)

    @ddt.data(
        {
            'compatible': False,
            'writable': True,
            'nondisruptive': True,
            'preserve_snapshots': True,
        },
        {
            'compatible': True,
            'writable': False,
            'nondisruptive': True,
            'preserve_snapshots': True,
        },
        {
            'compatible': True,
            'writable': True,
            'nondisruptive': False,
            'preserve_snapshots': True,
        },
        {
            'compatible': True,
            'writable': True,
            'nondisruptive': True,
            'preserve_snapshots': False,
        },
        {
            'compatible': True,
            'writable': True,
            'nondisruptive': True,
            'preserve_snapshots': False,
            'not_preserve_with_instances': True
        },
    )
    @ddt.unpack
    def test__validate_check_compatibility_result(
            self, compatible, writable, nondisruptive,
            preserve_snapshots, not_preserve_with_instances=False):
        fake_share_network = db_utils.create_share_network()
        fake_share_server = db_utils.create_share_server()
        fake_share_server_dest = db_utils.create_share_server()
        share_instances = []
        snapshot_instances = [
            db_utils.create_snapshot(
                with_share=True, status='available')['instance']]

        driver_compatibility = {
            'compatible': compatible,
            'writable': writable,
            'preserve_snapshots': preserve_snapshots,
            'nondisruptive': nondisruptive,
            'share_network_id': fake_share_network['id'],
            'migration_cancel': False,
            'migration_get_progress': False
        }
        specified_writable = True if not writable else writable
        specified_nondisruptive = True if not nondisruptive else nondisruptive
        specified_preserve_snapshots = (True if not preserve_snapshots else
                                        preserve_snapshots)
        if not preserve_snapshots and not_preserve_with_instances:
            specified_preserve_snapshots = False

        self.assertRaises(
            exception.ShareServerMigrationFailed,
            self.share_manager._validate_check_compatibility_result,
            self.context,
            fake_share_server['id'],
            share_instances,
            snapshot_instances,
            driver_compatibility,
            fake_share_server_dest['host'],
            specified_nondisruptive,
            specified_writable,
            specified_preserve_snapshots,
            resource_type='share server'
        )

    @ddt.data(
        {
            'kwargs': {'share_instance_ids': ['fakeid1']},
            'resource_type': 'share_instance'
        },
        {
            'kwargs': {'snapshot_instance_ids': ['fakeid1']},
            'resource_type': 'snapshot_instance'
        },
        {
            'kwargs': {
                'snapshot_instance_ids': ['fakeid1'],
                'task_state': constants.TASK_STATE_MIGRATION_STARTING},
            'resource_type': 'snapshot_instance'
        },
    )
    @ddt.unpack
    def test__update_resource_status(self, kwargs, resource_type):
        if resource_type == 'share_instance':
            mock_db_instances_status_update = self.mock_object(
                db, 'share_instances_status_update')
        else:
            mock_db_instances_status_update = self.mock_object(
                db, 'share_snapshot_instances_status_update')

        kwargs_relationship = {
            'share_instance': 'share_instance_ids',
            'snapshot_instance': 'snapshot_instance_ids'
        }
        resource_ids_key = kwargs_relationship.get(resource_type)
        resource_ids = kwargs.get(resource_ids_key)
        fields = {'status': constants.STATUS_AVAILABLE}
        if kwargs.get('task_state'):
            fields['task_state'] = kwargs['task_state']

        self.share_manager._update_resource_status(
            self.context, constants.STATUS_AVAILABLE, **kwargs)

        mock_db_instances_status_update.assert_called_once_with(
            self.context, resource_ids, fields)

    def _get_share_server_start_update_calls(
            self, source_share_server, dest_share_server, driver_failed=False):
        migration_in_progress_call = mock.call(
            self.context, dest_share_server['id'],
            {
                'status': constants.STATUS_SERVER_MIGRATING_TO,
                'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS,
                'source_share_server_id': source_share_server['id']
            }
        )
        driver_migration_starting_src_call = mock.call(
            self.context, source_share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_DRIVER_STARTING}
        )
        driver_migration_starting_dest_call = mock.call(
            self.context, dest_share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_DRIVER_STARTING}
        )
        driver_migration_src_call = mock.call(
            self.context, source_share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS}
        )
        driver_migration_dest_call = mock.call(
            self.context, dest_share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS}
        )
        driver_migration_dest_error = mock.call(
            self.context, dest_share_server['id'],
            {
                'task_state': constants.TASK_STATE_MIGRATION_ERROR,
                'status': constants.STATUS_ERROR
            }
        )
        mock_calls = [
            migration_in_progress_call, driver_migration_starting_src_call,
            driver_migration_starting_dest_call]
        if driver_failed:
            mock_calls.append(driver_migration_dest_error)
        else:
            mock_calls.append(driver_migration_src_call)
            mock_calls.append(driver_migration_dest_call)
        return mock_calls

    def _setup_server_migration_start_mocks(
            self, fake_share_instances, fake_snap_instances, fake_old_network,
            fake_new_network, fake_service, fake_request_spec,
            fake_driver_result, fake_new_share_server, server_info,
            network_subnet, new_network_subnet=None, az_compatible=True):
        self.mock_object(db, 'share_instances_get_all_by_share_server',
                         mock.Mock(return_value=fake_share_instances))
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=fake_snap_instances))
        self.mock_object(db, 'share_network_get',
                         mock.Mock(side_effect=[fake_old_network,
                                                fake_new_network]))
        self.mock_object(self.share_manager, '_update_resource_status')
        self.mock_object(db, 'service_get_by_args',
                         mock.Mock(return_value=fake_service))
        self.mock_object(api.API,
                         'get_share_server_migration_request_spec_dict',
                         mock.Mock(return_value=fake_request_spec))
        self.mock_object(self.share_manager.driver,
                         'share_server_migration_check_compatibility',
                         mock.Mock(return_value=fake_driver_result))
        self.mock_object(self.share_manager,
                         '_validate_check_compatibility_result')
        self.mock_object(self.share_manager,
                         '_provide_share_server_for_migration',
                         mock.Mock(return_value=fake_new_share_server))
        self.mock_object(self.share_manager,
                         '_cast_access_rules_to_readonly_for_server')
        self.mock_object(db, 'share_network_subnet_get',
                         mock.Mock(return_value=network_subnet))
        self.mock_object(db, 'share_network_subnet_get_all_by_share_server_id',
                         mock.Mock(return_value=[new_network_subnet]))
        self.mock_object(db, 'share_server_get',
                         mock.Mock(return_value=fake_new_share_server))
        self.mock_object(self.share_manager.driver, 'allocate_network')
        self.mock_object(self.share_manager.driver, 'allocate_admin_network')
        self.mock_object(self.share_manager.driver,
                         'deallocate_network')
        self.mock_object(db, 'share_server_delete')
        self.mock_object(db, 'share_server_update')
        self.mock_object(self.share_manager.driver,
                         'share_server_migration_start',
                         mock.Mock(return_value=server_info))
        self.mock_object(db, 'share_server_backend_details_set')
        self.mock_object(self.share_manager, 'delete_share_server')
        self.mock_object(share_utils, 'is_az_subnets_compatible',
                         mock.Mock(return_value=az_compatible))

    @ddt.data((True, True), (False, True))
    @ddt.unpack
    def test__share_server_migration_start_driver(self, writable,
                                                  nondisruptive):
        old_subnet_id = 'fake_id'
        new_subnet_kwargs = {}
        if not nondisruptive:
            new_subnet_kwargs.update({
                'neutron_net_id': 'fake_nn_id',
                'neutron_subnet_id': 'fake_sn_id'
            })

        network_subnet = db_utils.create_share_network_subnet(id=old_subnet_id)
        new_network_subnet = db_utils.create_share_network_subnet(
            **new_subnet_kwargs)
        fake_old_share_server = {
            'id': 'fake_server_id',
            'share_network_subnets': [network_subnet],
            'host': 'host@backend'
        }
        fake_new_share_server = {
            'id': 'fake_server_id_2',
            'share_network_subnets': [new_network_subnet],
            'host': 'host@backend'
        }

        fake_old_network = db_utils.create_share_network()
        fake_new_network = db_utils.create_share_network()
        fake_share_instances = [
            db_utils.create_share(
                share_server_id=fake_old_share_server['id'],
                share_network_id=fake_old_network['id'])['instance']]
        fake_share_instance_ids = [
            fake_instance['id'] for fake_instance in fake_share_instances]
        fake_snap_instances = []
        fake_service = {'availability_zone_id': 'fake_az_id',
                        'availability_zone': {'name': 'fake_az1'}}
        fake_request_spec = {}
        fake_dest_host = 'fakehost@fakebackend'
        preserve_snapshots = True
        fake_driver_result = {
            'compatible': True,
            'writable': writable,
            'preserve_snapshots': preserve_snapshots,
            'nondisruptive': nondisruptive,
            'share_network_id': fake_new_network['id'],
            'migration_cancel': False,
            'migration_get_progress': False
        }
        server_info = {
            'fake_server_info_key': 'fake_server_info_value',
            'backend_details': {'fake': 'fake'}
        }
        create_on_backend = not nondisruptive
        self._setup_server_migration_start_mocks(
            fake_share_instances, fake_snap_instances, fake_old_network,
            fake_new_network, fake_service, fake_request_spec,
            fake_driver_result, fake_new_share_server, server_info,
            network_subnet, new_network_subnet=new_network_subnet,
            az_compatible=create_on_backend)

        result = self.share_manager._share_server_migration_start_driver(
            self.context, fake_old_share_server, fake_dest_host, writable,
            nondisruptive, preserve_snapshots, fake_new_network['id'])

        self.assertTrue(result)
        db.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, fake_old_share_server['id'], with_share_data=True)
        (db.share_snapshot_instance_get_all_with_filters.
            assert_called_once_with(
                self.context, {'share_instance_ids': fake_share_instance_ids}))
        db.share_network_get.assert_has_calls(
            [mock.call(self.context, fake_old_network['id']),
             mock.call(self.context, fake_new_network['id'])])
        db.service_get_by_args.assert_called_once_with(
            self.context, fake_dest_host, 'manila-share')
        (api.API.get_share_server_migration_request_spec_dict.
            assert_called_once_with(
                self.context, fake_share_instances, fake_snap_instances,
                availability_zone_id=fake_service['availability_zone_id'],
                share_network_id=fake_new_network['id']))
        (self.share_manager.driver.share_server_migration_check_compatibility.
            assert_called_once_with(
                self.context, fake_old_share_server, fake_dest_host,
                fake_old_network, fake_new_network, fake_request_spec))
        (self.share_manager._validate_check_compatibility_result.
            assert_called_once_with(
                self.context, fake_old_share_server, fake_share_instances,
                fake_snap_instances, fake_driver_result, fake_dest_host,
                nondisruptive, writable, preserve_snapshots,
                resource_type='share server'))
        (self.share_manager._provide_share_server_for_migration.
            assert_called_once_with(
                self.context, fake_old_share_server, fake_new_network['id'],
                fake_service['availability_zone_id'], fake_dest_host,
                create_on_backend=create_on_backend))
        db.share_server_update.assert_has_calls(
            self._get_share_server_start_update_calls(
                fake_old_share_server, fake_new_share_server))
        (self.share_manager.driver.share_server_migration_start.
            assert_called_once_with(
                self.context, fake_old_share_server, fake_new_share_server,
                fake_share_instances, fake_snap_instances))
        if not create_on_backend:
            share_utils.is_az_subnets_compatible.assert_called_once_with(
                [new_network_subnet], [network_subnet])
            (db.share_network_subnet_get_all_by_share_server_id.
                assert_called_once_with(
                    self.context, fake_new_share_server['id']))
            self.share_manager.driver.allocate_network.assert_called_once_with(
                self.context, fake_new_share_server, fake_new_network,
                new_network_subnet)
            (self.share_manager.driver.allocate_admin_network.
             assert_called_once_with(self.context, fake_new_share_server))

        if not writable:
            (self.share_manager._cast_access_rules_to_readonly_for_server.
                assert_called_once_with(
                    self.context, fake_share_instances, fake_old_share_server,
                    dest_host=fake_old_share_server['host']))
        else:
            (self.share_manager._cast_access_rules_to_readonly_for_server.
             assert_not_called())
        if server_info:
            db.share_server_backend_details_set.assert_called_once_with(
                self.context, fake_new_share_server['id'],
                server_info.get('backend_details'))

    def test__share_server_migration_start_driver_exception(self):
        fake_old_share_server = db_utils.create_share_server()
        fake_new_share_server = db_utils.create_share_server()
        fake_old_network = db_utils.create_share_network()
        fake_new_network = db_utils.create_share_network()
        fake_share_instances = [
            db_utils.create_share(
                share_server_id=fake_old_share_server['id'],
                share_network_id=fake_old_network['id'])['instance']]
        fake_share_instance_ids = [
            fake_instance['id'] for fake_instance in fake_share_instances]
        fake_snap_instances = []
        fake_snap_instance_ids = []
        fake_service = {'availability_zone_id': 'fake_az_id',
                        'availability_zone': {'name': 'fake_az1'}}
        fake_request_spec = {}
        fake_dest_host = 'fakehost@fakebackend'
        nondisruptive = False
        preserve_snapshots = True
        writable = True
        fake_driver_result = {
            'compatible': True,
            'writable': writable,
            'preserve_snapshots': preserve_snapshots,
            'nondisruptive': nondisruptive,
            'share_network_id': fake_new_network['id'],
            'migration_cancel': False,
            'migration_get_progress': False
        }
        server_info = {
            'fake_server_info_key': 'fake_server_info_value',
            'backend_details': {'fake': 'fake'}
        }
        network_subnet = db_utils.create_share_network_subnet()

        self._setup_server_migration_start_mocks(
            fake_share_instances, fake_snap_instances, fake_old_network,
            fake_new_network, fake_service, fake_request_spec,
            fake_driver_result, fake_new_share_server, server_info,
            network_subnet)
        mock__reset_read_only = self.mock_object(
            self.share_manager, '_reset_read_only_access_rules_for_server')

        self.share_manager.driver.share_server_migration_start.side_effect = (
            Exception
        )

        self.assertRaises(
            exception.ShareServerMigrationFailed,
            self.share_manager._share_server_migration_start_driver,
            self.context, fake_old_share_server, fake_dest_host, writable,
            nondisruptive, preserve_snapshots, fake_new_network['id']
        )

        db.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, fake_old_share_server['id'], with_share_data=True)
        (db.share_snapshot_instance_get_all_with_filters.
            assert_called_once_with(
                self.context, {'share_instance_ids': fake_share_instance_ids}))
        db.share_network_get.assert_has_calls(
            [mock.call(self.context, fake_old_network['id']),
             mock.call(self.context, fake_new_network['id'])])
        self.share_manager._update_resource_status.assert_has_calls([
            mock.call(
                self.context, constants.STATUS_AVAILABLE,
                share_instance_ids=fake_share_instance_ids,
                snapshot_instance_ids=fake_snap_instance_ids)])
        db.service_get_by_args.assert_called_once_with(
            self.context, fake_dest_host, 'manila-share')
        (api.API.get_share_server_migration_request_spec_dict.
            assert_called_once_with(
                self.context, fake_share_instances, fake_snap_instances,
                availability_zone_id=fake_service['availability_zone_id'],
                share_network_id=fake_new_network['id']))
        (self.share_manager.driver.share_server_migration_check_compatibility.
            assert_called_once_with(
                self.context, fake_old_share_server, fake_dest_host,
                fake_old_network, fake_new_network, fake_request_spec))
        (self.share_manager._validate_check_compatibility_result.
            assert_called_once_with(
                self.context, fake_old_share_server, fake_share_instances,
                fake_snap_instances, fake_driver_result, fake_dest_host,
                nondisruptive, writable, preserve_snapshots,
                resource_type='share server'))
        (self.share_manager._provide_share_server_for_migration.
            assert_called_once_with(
                self.context, fake_old_share_server, fake_new_network['id'],
                fake_service['availability_zone_id'], fake_dest_host,
                create_on_backend=True))
        db.share_server_update.assert_has_calls(
            self._get_share_server_start_update_calls(
                fake_old_share_server, fake_new_share_server,
                driver_failed=True))
        (self.share_manager.driver.share_server_migration_start.
            assert_called_once_with(
                self.context, fake_old_share_server, fake_new_share_server,
                fake_share_instances, fake_snap_instances))
        mock__reset_read_only.assert_called_once_with(
            self.context, fake_share_instances, fake_old_share_server,
            dest_host=fake_old_share_server['host']
        )

        if not writable:
            (self.share_manager._cast_access_rules_to_readonly_for_server.
                assert_called_once_with(
                    self.context, fake_share_instances, fake_old_share_server,
                    fake_old_share_server['host']))
        else:
            (self.share_manager._cast_access_rules_to_readonly_for_server.
             assert_not_called())
        self.share_manager.delete_share_server.assert_called_once_with(
            self.context, fake_new_share_server)

    @ddt.data(None, exception.ShareServerMigrationFailed)
    def test_share_server_migration_check(self, check_action):
        fake_share_server = db_utils.create_share_server()
        fake_old_network = db_utils.create_share_network()
        fake_new_network = db_utils.create_share_network()
        fake_dest_host = 'fakehost@fakebackend'
        fake_share_instances = [
            db_utils.create_share(
                share_network_id=fake_old_network['id'])['instance']]
        fake_share_instance_ids = [
            fake_instance['id'] for fake_instance in fake_share_instances]
        fake_snap_instances = []
        fake_service = {'availability_zone_id': 'fake_az_id',
                        'availability_zone': {'name': 'fake_az1'}}
        fake_request_spec = {}
        nondisruptive = False
        writable = True
        preserve_snapshots = True
        fake_driver_result = {
            'compatible': True,
            'writable': writable,
            'preserve_snapshots': preserve_snapshots,
            'nondisruptive': nondisruptive,
            'share_network_id': fake_new_network['id'],
            'migration_cancel': False,
            'migration_get_progress': False
        }

        mock_server_get = self.mock_object(
            db, 'share_server_get', mock.Mock(return_value=fake_share_server))
        mock_get_server_instances = self.mock_object(
            db, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=fake_share_instances))
        mock_snap_instances_get = self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=fake_snap_instances))
        mock_sn_get = self.mock_object(
            db, 'share_network_get',
            mock.Mock(side_effect=[fake_old_network, fake_new_network]))
        mock_service_get = self.mock_object(
            db, 'service_get_by_args', mock.Mock(return_value=fake_service))
        mock_get_req_spec = self.mock_object(
            api.API, 'get_share_server_migration_request_spec_dict',
            mock.Mock(return_value=fake_request_spec))
        mock_driver_check = self.mock_object(
            self.share_manager.driver,
            'share_server_migration_check_compatibility',
            mock.Mock(return_value=fake_driver_result))
        mock__validate_check_compatibility = self.mock_object(
            self.share_manager, '_validate_check_compatibility_result')
        if isinstance(check_action, exception.ShareServerMigrationFailed):
            mock__validate_check_compatibility.side_effect = (
                exception.ShareServerMigrationFailed)
            fake_driver_result['compatible'] = False

        result = self.share_manager.share_server_migration_check(
            self.context, fake_share_server['id'], fake_dest_host, True, False,
            True, fake_new_network['id']
        )

        self.assertEqual(fake_driver_result, result)
        mock_server_get.assert_called_once_with(
            self.context, fake_share_server['id'])
        mock_get_server_instances.assert_called_once_with(
            self.context, fake_share_server['id'], with_share_data=True
        )
        mock_snap_instances_get.assert_called_once_with(
            self.context, {'share_instance_ids': fake_share_instance_ids}
        )
        mock_sn_get.assert_has_calls(
            [mock.call(self.context, fake_old_network['id']),
             mock.call(self.context, fake_new_network['id'])]
        )
        mock_service_get.assert_called_once_with(
            self.context, fake_dest_host, 'manila-share'
        )
        mock_get_req_spec.assert_called_once_with(
            self.context, fake_share_instances, fake_snap_instances,
            availability_zone_id=fake_service['availability_zone_id'],
            share_network_id=fake_new_network['id']
        )
        mock_driver_check.assert_called_once_with(
            self.context, fake_share_server, fake_dest_host, fake_old_network,
            fake_new_network, fake_request_spec
        )
        mock__validate_check_compatibility.assert_called_once_with(
            self.context, fake_share_server, fake_share_instances,
            fake_snap_instances, fake_driver_result, fake_dest_host,
            nondisruptive, writable, preserve_snapshots,
            resource_type='share server'
        )

    def test_share_server_migration_check_dhss_false(self):
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = False
        expected = {
            'compatible': False,
            'writable': None,
            'preserve_snapshots': None,
            'nondisruptive': None,
            'share_network_id': 'new_share_network_id',
            'migration_cancel': None,
            'migration_get_progress': None
        }

        result = self.share_manager.share_server_migration_check(
            self.context, 'fake_share_server_id', 'fake_dest_host',
            False, False, False, 'new_share_network_id'
        )

        self.assertEqual(expected, result)

    def test_share_server_migration_start(self):
        fake_share_server = db_utils.create_share_server()
        fake_share_network = db_utils.create_share_server()
        fake_dest_host = 'fakehost@fakebackend'
        writable = True
        nondisruptive = True
        preserve_snapshots = True

        mock_server_update = self.mock_object(db, 'share_server_update')
        mock_server_get = self.mock_object(
            db, 'share_server_get', mock.Mock(return_value=fake_share_server))
        mock__server_migration_start_driver = self.mock_object(
            self.share_manager, '_share_server_migration_start_driver')

        self.share_manager.share_server_migration_start(
            self.context, fake_share_server['id'], fake_dest_host, writable,
            nondisruptive, preserve_snapshots, fake_share_network['id']
        )

        mock_server_update.assert_called_once_with(
            self.context, fake_share_server['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS}
        )
        mock_server_get.assert_called_once_with(
            self.context, fake_share_server['id']
        )
        mock__server_migration_start_driver.assert_called_once_with(
            self.context, fake_share_server, fake_dest_host, writable,
            nondisruptive, preserve_snapshots, fake_share_network['id']
        )

    @ddt.data(True, False)
    def test_share_server_migration_start_exception(self, dhss):
        fake_share_server = db_utils.create_share_server()
        fake_share_network = db_utils.create_share_server()
        fake_dest_host = 'fakehost@fakebackend'
        writable = True
        nondisruptive = True
        preserve_snapshots = True
        self.mock_object(self.share_manager, 'driver')
        self.share_manager.driver.driver_handles_share_servers = dhss

        mock_server_update = self.mock_object(db, 'share_server_update')
        mock_server_get = self.mock_object(
            db, 'share_server_get', mock.Mock(return_value=fake_share_server))
        mock__server_migration_start_driver = self.mock_object(
            self.share_manager, '_share_server_migration_start_driver',
            mock.Mock(side_effect=exception.ShareServerMigrationFailed(
                reason='fake_reason')))

        self.share_manager.share_server_migration_start(
            self.context, fake_share_server['id'], fake_dest_host, writable,
            nondisruptive, preserve_snapshots, fake_share_network['id']
        )

        mock_server_update.assert_has_calls([
            mock.call(
                self.context, fake_share_server['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_IN_PROGRESS}),
            mock.call(
                self.context, fake_share_server['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_ERROR,
                 'status': constants.STATUS_ACTIVE}
            )
        ])
        mock_server_get.assert_called_once_with(
            self.context, fake_share_server['id']
        )
        if dhss:
            mock__server_migration_start_driver.assert_called_once_with(
                self.context, fake_share_server, fake_dest_host, writable,
                nondisruptive, preserve_snapshots, fake_share_network['id']
            )

    def _setup_migration_continue_mocks(
            self, fake_share_servers, fake_share_instances,
            fake_snapshot_instances):
        self.mock_object(
            db, 'share_server_get_all_by_host',
            mock.Mock(return_value=fake_share_servers))
        self.mock_object(
            db, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=fake_share_instances))
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=fake_snapshot_instances))

    @ddt.data(True, False)
    def test_share_server_migration_continue(self, finished):
        fake_src_share_servers = [
            db_utils.create_share_server(
                status=constants.STATUS_SERVER_MIGRATING,
                task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)]
        fake_dest_share_servers = [
            db_utils.create_share_server(
                source_share_server_id=fake_src_share_servers[0]['id'],
                status=constants.STATUS_SERVER_MIGRATING_TO,
                task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS
            )]
        fake_share_instances = [db_utils.create_share()['instance']]
        fake_share_instance_ids = [
            instance['id'] for instance in fake_share_instances]
        fake_cancelled_share_server = db_utils.create_share_server()
        fake_snapshot_instances = []
        server_update_calls = [
            mock.call(
                self.context, fake_src_share_servers[0]['id'],
                {
                    'task_state':
                        constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE}),
            mock.call(
                self.context, fake_dest_share_servers[0]['id'],
                {
                    'task_state':
                        constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE
                })
            ]

        self._setup_migration_continue_mocks(
            fake_dest_share_servers, fake_share_instances,
            fake_snapshot_instances)
        self.mock_object(db, 'share_server_get',
                         mock.Mock(side_effect=[fake_src_share_servers[0],
                                                fake_cancelled_share_server]))
        self.mock_object(
            self.share_manager.driver, 'share_server_migration_continue',
            mock.Mock(return_value=finished))
        self.mock_object(db, 'share_server_update')

        self.share_manager.share_server_migration_driver_continue(
            self.context)

        db.share_server_get_all_by_host.assert_called_once_with(
            self.context, self.share_manager.host,
            filters={'status': constants.STATUS_SERVER_MIGRATING_TO}
        )
        db.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, fake_src_share_servers[0]['id'],
            with_share_data=True
        )
        (db.share_snapshot_instance_get_all_with_filters.
            assert_called_once_with(
                self.context, {'share_instance_ids': fake_share_instance_ids}))
        (self.share_manager.driver.share_server_migration_continue.
            assert_called_once_with(
                self.context, fake_src_share_servers[0],
                fake_dest_share_servers[0],
                fake_share_instances, fake_snapshot_instances))
        if finished:
            db.share_server_update.assert_has_calls(server_update_calls)
            db.share_server_get.assert_called_once_with(
                self.context, fake_src_share_servers[0]['id']
            )
        else:
            db.share_server_get.assert_has_calls([
                mock.call(self.context, fake_src_share_servers[0]['id']),
                mock.call(self.context, fake_src_share_servers[0]['id']),
            ])

    @ddt.data(
        {
            'src_share_server_exists': False,
            'action_migration_continue': {
                'return_value': True
            }
        },
        {
            'src_share_server_exists': True,
            'action_migration_continue': {
                'side_effect': Exception
            }
        }
    )
    @ddt.unpack
    def test_share_server_migration_continue_exception(
            self, src_share_server_exists, action_migration_continue):
        fake_src_share_server = db_utils.create_share_server(
            status=constants.STATUS_SERVER_MIGRATING,
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)
        fake_dest_share_servers = [
            db_utils.create_share_server(
                source_share_server_id=fake_src_share_server['id'],
                status=constants.STATUS_SERVER_MIGRATING_TO,
                task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)]
        fake_share_instances = [db_utils.create_share()['instance']]
        fake_share_instance_ids = [
            instance['id'] for instance in fake_share_instances]
        fake_snapshot_instances = []
        fake_snapshot_instance_ids = []

        server_update_calls = [mock.call(
            self.context, fake_dest_share_servers[0]['id'],
            {'task_state': constants.TASK_STATE_MIGRATION_ERROR,
             'status': constants.STATUS_ERROR}
        )]
        if src_share_server_exists:
            self.mock_object(db, 'share_server_get',
                             mock.Mock(return_value=fake_src_share_server))
            server_update_calls.append(
                mock.call(
                    self.context, fake_src_share_server['id'],
                    {
                        'task_state': constants.TASK_STATE_MIGRATION_ERROR,
                        'status': constants.STATUS_ACTIVE
                    }))
        else:
            self.mock_object(db, 'share_server_get',
                             mock.Mock(return_value=None))

        self._setup_migration_continue_mocks(
            fake_dest_share_servers, fake_share_instances,
            fake_snapshot_instances)
        mock_server_update = self.mock_object(db, 'share_server_update')
        self.mock_object(
            self.share_manager.driver, 'share_server_migration_continue',
            mock.Mock(**action_migration_continue)
        )
        mock__update_resource_status = self.mock_object(
            self.share_manager, '_update_resource_status')
        mock__rest_read_only_access_rules = self.mock_object(
            self.share_manager, '_reset_read_only_access_rules_for_server'
        )

        self.share_manager.share_server_migration_driver_continue(
            self.context)

        db.share_server_get_all_by_host.assert_called_once_with(
            self.context, self.share_manager.host,
            filters={'status': constants.STATUS_SERVER_MIGRATING_TO})
        db.share_server_get.assert_called_once_with(
            self.context, fake_src_share_server['id'])
        if src_share_server_exists:
            db.share_instances_get_all_by_share_server.assert_called_once_with(
                self.context, fake_src_share_server['id'],
                with_share_data=True)
            (db.share_snapshot_instance_get_all_with_filters.
                assert_called_once_with(
                    self.context,
                    {'share_instance_ids': fake_share_instance_ids}))
            mock__update_resource_status.assert_called_once_with(
                self.context, constants.STATUS_AVAILABLE,
                share_instance_ids=fake_share_instance_ids,
                snapshot_instance_ids=fake_snapshot_instance_ids
            )
            mock__rest_read_only_access_rules.assert_called_once_with(
                self.context, fake_share_instances, fake_src_share_server,
                dest_host=fake_src_share_server['host']
            )
            mock_server_update.assert_has_calls(server_update_calls)

    def _setup_server_migration_complete_mocks(
            self, fake_source_share_server, fake_dest_share_server,
            fake_share_instances, fake_snapshot_instances,
            additional_server_get_side_effect=None):
        server_get_side_effects = [fake_dest_share_server,
                                   fake_source_share_server]
        if additional_server_get_side_effect:
            server_get_side_effects.append(additional_server_get_side_effect)

        self.mock_object(
            db, 'share_server_get',
            mock.Mock(side_effect=server_get_side_effects))
        self.mock_object(
            db, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=fake_share_instances))
        self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=fake_snapshot_instances))
        self.mock_object(
            self.share_manager, '_update_resource_status')
        self.mock_object(db, 'share_server_update')

    @ddt.data(True, False)
    def test_share_server_migration_complete_exception(
            self, server_already_dropped):
        fake_source_share_server = db_utils.create_share_server()
        fake_dest_share_server = db_utils.create_share_server()
        fake_share_instances = [db_utils.create_share()['instance']]
        fake_share_instance_ids = [
            instance['id'] for instance in fake_share_instances]
        fake_snapshot_instances = []
        fake_snapshot_instance_ids = []
        server_get_additional_se = (
            exception.ShareServerNotFound
            if server_already_dropped else fake_dest_share_server)
        server_update_calls = [
            mock.call(self.context, fake_source_share_server['id'],
                      {'task_state': constants.TASK_STATE_MIGRATION_ERROR,
                       'status': constants.STATUS_ERROR}),
        ]
        if not server_already_dropped:
            server_update_calls.append(
                mock.call(
                    self.context, fake_dest_share_server['id'],
                    {'task_state': constants.TASK_STATE_MIGRATION_ERROR,
                     'status': constants.STATUS_ERROR})
            )

        self._setup_server_migration_complete_mocks(
            fake_source_share_server, fake_dest_share_server,
            fake_share_instances, fake_snapshot_instances,
            server_get_additional_se)
        mock__server_migration_complete = self.mock_object(
            self.share_manager, '_server_migration_complete_driver',
            mock.Mock(side_effect=Exception))

        self.assertRaises(
            exception.ShareServerMigrationFailed,
            self.share_manager.share_server_migration_complete,
            self.context, fake_source_share_server['id'],
            fake_dest_share_server['id']
        )
        db.share_server_get.assert_has_calls(
            [mock.call(self.context, fake_dest_share_server['id']),
             mock.call(self.context, fake_source_share_server['id'])]
        )
        db.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, fake_source_share_server['id'], with_share_data=True)
        (db.share_snapshot_instance_get_all_with_filters.
            assert_called_once_with(
                self.context, {'share_instance_ids': fake_share_instance_ids}))
        mock__server_migration_complete.assert_called_once_with(
            self.context, fake_source_share_server, fake_share_instances,
            fake_snapshot_instances, fake_dest_share_server)
        self.share_manager._update_resource_status.assert_called_once_with(
            self.context, constants.STATUS_ERROR,
            share_instance_ids=fake_share_instance_ids,
            snapshot_instance_ids=fake_snapshot_instance_ids)
        db.share_server_update.assert_has_calls(server_update_calls)

    @ddt.data(('fake_src_identifier', 'fake_dest_identifier'),
              ('fake_src_identifier', None))
    @ddt.unpack
    def test_share_server_migration_complete(
            self, src_identifier, dest_identifier):
        fake_source_share_server = db_utils.create_share_server(
            identifier=src_identifier)
        fake_dest_share_server = db_utils.create_share_server(
            identifier=dest_identifier)
        fake_share_instances = [db_utils.create_share()['instance']]
        fake_share_instance_ids = [
            instance['id'] for instance in fake_share_instances]
        fake_snapshot_instances = []
        fake_snapshot_instance_ids = []
        expected_identifier = (
            dest_identifier if dest_identifier else src_identifier)
        expected_server_update = {
            'task_state': constants.TASK_STATE_MIGRATION_SUCCESS,
            'status': constants.STATUS_ACTIVE,
        }
        if not dest_identifier:
            expected_server_update['identifier'] = expected_identifier
        self._setup_server_migration_complete_mocks(
            fake_source_share_server, fake_dest_share_server,
            fake_share_instances, fake_snapshot_instances
        )
        mock__server_migration_complete = self.mock_object(
            self.share_manager, '_server_migration_complete_driver')

        self.share_manager.share_server_migration_complete(
            self.context, fake_source_share_server['id'],
            fake_dest_share_server['id'])
        db.share_server_get.assert_has_calls(
            [mock.call(self.context, fake_dest_share_server['id']),
             mock.call(self.context, fake_source_share_server['id'])]
        )
        db.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, fake_source_share_server['id'], with_share_data=True)
        (db.share_snapshot_instance_get_all_with_filters.
            assert_called_once_with(
                self.context, {'share_instance_ids': fake_share_instance_ids}))
        mock__server_migration_complete.assert_called_once_with(
            self.context, fake_source_share_server, fake_share_instances,
            fake_snapshot_instances, fake_dest_share_server)
        self.share_manager._update_resource_status.assert_called_once_with(
            self.context, constants.STATUS_AVAILABLE,
            share_instance_ids=fake_share_instance_ids,
            snapshot_instance_ids=fake_snapshot_instance_ids)
        db.share_server_update.assert_called_once_with(
            self.context, fake_dest_share_server['id'],
            expected_server_update)

    @ddt.data(
        {'model_update': {
            'unmanage_source_server': False,
            'snapshot_updates': {},
            'share_updates': {}},
            'need_network_allocation': False,
            'can_reuse_server': False},
        {'model_update': {
            'unmanage_source_server': True,
            'snapshot_updates': {},
            'share_updates': {}},
            'need_network_allocation': False,
            'can_reuse_server': True},
        {'model_update': {
            'unmanage_source_server': False,
            'snapshot_updates': {},
            'share_updates': {}},
            'need_network_allocation': True,
            'can_reuse_server': False},
        {'model_update': {
            'unmanage_source_server': True,
            'snapshot_updates': {},
            'share_updates': {}},
            'need_network_allocation': True,
            'can_reuse_server': True}
    )
    @ddt.unpack
    def test__server_migration_complete_driver(self, model_update,
                                               need_network_allocation,
                                               can_reuse_server):
        fake_share_network = db_utils.create_share_network()
        fake_share_network_subnet = db_utils.create_share_network_subnet(
            share_network_id=fake_share_network['id'])
        fake_source_share_server = db_utils.create_share_server()
        fake_dest_share_server = db_utils.create_share_server(
            share_network_subnets=[fake_share_network_subnet])
        fake_share = db_utils.create_share()
        fake_snapshot = db_utils.create_snapshot(share_id=fake_share['id'])
        fake_service = {'availability_zone_id': 'fake_az_id',
                        'availability_zone': {'name': 'fake_az1'}}
        fake_share_instances = [fake_share['instance']]
        fake_snapshot_instances = [fake_snapshot['instance']]
        fake_share_instance_id = fake_share['instance']['id']
        fake_alloc_data = [{
            'network_allocations': [{'id': 'fake_id'}],
            'admin_network_allocations': [{'id': 'fake_admin_id'}],
        }]
        model_update['share_updates'][fake_share['instance']['id']] = {
            'export_locations': {
                "path": "10.10.10.31:/fake_mount_point",
                "metadata": {
                    "preferred": True,
                },
                "is_admin_only": False,
            },
            'pool_name': 'fakepool'
        }
        snapshot_el_update = {
            "path": "10.10.10.31:/fake_snap_mount_point",
            "is_admin_only": False,
        }
        model_update['snapshot_updates'][fake_snapshot['instance']['id']] = {
            'export_locations': [snapshot_el_update]
        }
        fake_instance_update = {
            'share_server_id': fake_dest_share_server['id'],
            'host': fake_dest_share_server['host'] + '#fakepool',
            'share_network_id': fake_share_network['id'],
            'availability_zone_id': fake_service['availability_zone_id'],
        }
        backend_details = fake_source_share_server.get("backend_details")
        mock_backend_details_set_calls = []
        if backend_details:
            for k, v in backend_details.items():
                mock_backend_details_set_calls.append(
                    mock.call(
                        self.context, fake_dest_share_server['id'],
                        {k: v})
                )

        dest_network_allocations = []
        if need_network_allocation:
            dest_network_allocations.append({'id': 'fake_allocation'})

        mock_server_update = self.mock_object(db, 'share_server_update')
        mock_network_get = self.mock_object(
            db, 'share_network_get',
            mock.Mock(return_value=fake_share_network))
        mock_allocations_get = self.mock_object(
            db, 'network_allocations_get_for_share_server',
            mock.Mock(return_value=dest_network_allocations)
        )
        mock_subnet_get = self.mock_object(
            db, 'share_network_subnet_get_all_by_share_server_id',
            mock.Mock(return_value=fake_share_network_subnet))
        mock_form_server_setup_info = self.mock_object(
            self.share_manager, '_form_server_setup_info',
            mock.Mock(return_value=fake_alloc_data))
        mock_server_migration_complete = self.mock_object(
            self.share_manager.driver, 'share_server_migration_complete',
            mock.Mock(return_value=model_update))
        mock_network_allocation_update = self.mock_object(
            db, 'network_allocation_update')
        mock_share_server_backend_details_set = self.mock_object(
            db, 'share_server_backend_details_set')
        mock_service_get_by_args = self.mock_object(
            db, 'service_get_by_args', mock.Mock(return_value=fake_service))
        mock_instance_update = self.mock_object(db, 'share_instance_update')
        mock_el_update = self.mock_object(db, 'share_export_locations_update')
        mock_snap_el_update = self.mock_object(
            db, 'share_snapshot_instance_export_locations_update')
        mock_reset_access_rules = self.mock_object(
            self.share_manager, '_reset_read_only_access_rules_for_server')
        mock_unmanage_server = self.mock_object(
            rpcapi.ShareAPI, 'unmanage_share_server')
        mock_delete_server = self.mock_object(db, 'share_server_delete')
        mock_deallocate_network = self.mock_object(
            self.share_manager.driver, 'deallocate_network')

        self.share_manager._server_migration_complete_driver(
            self.context, fake_source_share_server, fake_share_instances,
            fake_snapshot_instances, fake_dest_share_server)

        mock_server_update.assert_has_calls(
            [mock.call(
                self.context, fake_source_share_server['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING}),
             mock.call(
                 self.context, fake_dest_share_server['id'],
                 {'task_state': constants.TASK_STATE_MIGRATION_COMPLETING}),
             mock.call(
                 self.context, fake_source_share_server['id'],
                 {'task_state': constants.TASK_STATE_MIGRATION_SUCCESS,
                  'status': constants.STATUS_INACTIVE})])
        mock_network_get.assert_called_once_with(
            self.context, fake_share_network['id'])
        mock_subnet_get.assert_called_once_with(
            self.context, fake_dest_share_server['id'])
        mock_allocations_get.assert_called_once_with(
            self.context, fake_dest_share_server['id'])

        if not need_network_allocation:
            mock_form_server_setup_info.assert_called_once_with(
                self.context, fake_source_share_server, fake_share_network,
                fake_share_network_subnet)
        elif need_network_allocation:
            mock_share_server_backend_details_set.assert_has_calls(
                mock_backend_details_set_calls)
            mock_form_server_setup_info.assert_called_once_with(
                self.context, fake_dest_share_server, fake_share_network,
                fake_share_network_subnet)
            mock_network_allocation_update.assert_has_calls(
                [mock.call(
                    self.context,
                    fake_alloc_data[0]['network_allocations'][0]['id'],
                    {'share_server_id': fake_dest_share_server['id']}),
                 mock.call(
                    self.context,
                    fake_alloc_data[0]['admin_network_allocations'][0]['id'],
                    {'share_server_id': fake_dest_share_server['id']})])

        mock_server_migration_complete.assert_called_once_with(
            self.context, fake_source_share_server, fake_dest_share_server,
            fake_share_instances, fake_snapshot_instances, fake_alloc_data
        )
        mock_service_get_by_args.assert_called_once_with(
            self.context, fake_dest_share_server['host'], 'manila-share')
        mock_instance_update.assert_called_once_with(
            self.context, fake_share_instance_id, fake_instance_update)
        mock_el_update.assert_called_once_with(
            self.context, fake_share_instance_id,
            model_update['share_updates'][fake_share_instance_id][
                'export_locations'])
        mock_snap_el_update.assert_called_once_with(
            self.context, fake_snapshot['instance']['id'], [snapshot_el_update]
        )
        mock_reset_access_rules.assert_called_once_with(
            self.context, fake_share_instances, fake_source_share_server,
            dest_host=fake_source_share_server['host'])
        if model_update.get('unmanage_share_server') is True:
            mock_unmanage_server.assert_called_once_with(
                self.context, fake_source_share_server)
        else:
            mock_deallocate_network.assert_called_once_with(
                self.context, fake_source_share_server['id'])
            mock_delete_server.assert_called_once_with(
                self.context, fake_source_share_server['id'])

    @ddt.data(constants.TASK_STATE_MIGRATION_SUCCESS,
              constants.TASK_STATE_MIGRATION_IN_PROGRESS)
    def test_server_migration_cancel_exception(self, task_state):
        fake_source_share_server = db_utils.create_share_server(
            task_state=task_state)
        fake_dest_share_server = db_utils.create_share_server()

        mock_server_get = self.mock_object(
            db, 'share_server_get',
            mock.Mock(side_effect=[fake_source_share_server,
                                   fake_dest_share_server]))

        self.assertRaises(
            exception.InvalidShareServer,
            self.share_manager.share_server_migration_cancel,
            self.context, fake_source_share_server['id'],
            fake_dest_share_server['id']
        )

        mock_server_get.assert_has_calls([
            mock.call(self.context, fake_source_share_server['id']),
            mock.call(self.context, fake_dest_share_server['id'])])

    @ddt.data(
        constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
        constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)
    def test_share_server_migration_cancel(self, task_state):
        fake_source_share_server = db_utils.create_share_server(
            task_state=task_state)
        fake_dest_share_server = db_utils.create_share_server()
        fake_share = db_utils.create_share()
        fake_share_instances = [fake_share['instance']]
        fake_share_instance_ids = [fake_share['instance']['id']]
        fake_snapshot = db_utils.create_snapshot(share_id=fake_share['id'])
        fake_snapshot_instances = [fake_snapshot['instance']]
        fake_snapshot_instance_ids = [fake_snapshot['instance']['id']]

        mock_server_get = self.mock_object(
            db, 'share_server_get',
            mock.Mock(side_effect=[fake_source_share_server,
                                   fake_dest_share_server]))
        mock_get_instances = self.mock_object(
            db, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=fake_share_instances))
        mock_get_snap_instances = self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=fake_snapshot_instances))
        mock_migration_cancel = self.mock_object(
            self.share_manager.driver, 'share_server_migration_cancel')
        mock_server_update = self.mock_object(db, 'share_server_update')
        mock_check_delete_server = self.mock_object(
            self.share_manager, '_check_delete_share_server')
        mock_update_resource = self.mock_object(
            self.share_manager, '_update_resource_status')
        mock_reset_read_only_rules = self.mock_object(
            self.share_manager, '_reset_read_only_access_rules_for_server')

        self.share_manager.share_server_migration_cancel(
            self.context, fake_source_share_server['id'],
            fake_dest_share_server['id'])

        mock_server_get.assert_has_calls([
            mock.call(self.context, fake_source_share_server['id']),
            mock.call(self.context, fake_dest_share_server['id'])])
        mock_get_instances.assert_called_once_with(
            self.context, fake_source_share_server['id'], with_share_data=True)
        mock_get_snap_instances.assert_called_once_with(
            self.context, {'share_instance_ids': fake_share_instance_ids})
        mock_migration_cancel.assert_called_once_with(
            self.context, fake_source_share_server, fake_dest_share_server,
            fake_share_instances, fake_snapshot_instances)
        mock_server_update.assert_has_calls([
            mock.call(
                self.context, fake_dest_share_server['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED,
                 'status': constants.STATUS_INACTIVE}
            ),
            mock.call(
                self.context, fake_source_share_server['id'],
                {'task_state': constants.TASK_STATE_MIGRATION_CANCELLED,
                 'status': constants.STATUS_ACTIVE}
            )
        ])
        mock_check_delete_server.assert_called_once_with(
            self.context, share_server=fake_dest_share_server)
        mock_update_resource.assert_called_once_with(
            self.context, constants.STATUS_AVAILABLE,
            share_instance_ids=fake_share_instance_ids,
            snapshot_instance_ids=fake_snapshot_instance_ids)
        mock_reset_read_only_rules.assert_called_once_with(
            self.context, fake_share_instances, fake_source_share_server,
            dest_host=fake_source_share_server['host'])

    @ddt.data(
        constants.TASK_STATE_MIGRATION_STARTING,
        constants.TASK_STATE_MIGRATION_CANCELLED,
    )
    def test_migration_get_progress_exception(self, task_state):
        fake_source_share_server = db_utils.create_share_server(
            task_state=task_state)
        fake_dest_share_server = db_utils.create_share_server()

        self.mock_object(
            db, 'share_server_get',
            mock.Mock(side_effect=[fake_source_share_server,
                                   fake_dest_share_server]))

        self.assertRaises(
            exception.InvalidShareServer,
            self.share_manager.share_server_migration_cancel,
            self.context, fake_source_share_server['id'],
            fake_dest_share_server['id']
        )

    def test_share_server_migration_get_progress(self):
        fake_source_share_server = db_utils.create_share_server(
            task_state=constants.TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS)
        fake_dest_share_server = db_utils.create_share_server()
        fake_progress = {"total_progress": 75}
        fake_share = db_utils.create_share()
        fake_share_instances = [fake_share['instance']]
        fake_share_instance_ids = [fake_share['instance']['id']]
        fake_snapshot = db_utils.create_snapshot(share_id=fake_share['id'])
        fake_snapshot_instances = [fake_snapshot['instance']]

        mock_server_get = self.mock_object(
            db, 'share_server_get',
            mock.Mock(side_effect=[fake_source_share_server,
                                   fake_dest_share_server]))
        mock_get_instances = self.mock_object(
            db, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=fake_share_instances))
        mock_get_snap_instances = self.mock_object(
            db, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=fake_snapshot_instances))
        mock_migration_get_progress = self.mock_object(
            self.share_manager.driver, 'share_server_migration_get_progress',
            mock.Mock(return_value=fake_progress))

        self.share_manager.share_server_migration_get_progress(
            self.context, fake_source_share_server['id'],
            fake_dest_share_server['id'])

        mock_get_instances.assert_called_once_with(
            self.context, fake_source_share_server['id'], with_share_data=True)
        mock_get_snap_instances.assert_called_once_with(
            self.context, {'share_instance_ids': fake_share_instance_ids})
        mock_server_get.assert_has_calls([
            mock.call(self.context, fake_source_share_server['id']),
            mock.call(self.context, fake_dest_share_server['id'])])
        mock_migration_get_progress.assert_called_once_with(
            self.context, fake_source_share_server, fake_dest_share_server,
            fake_share_instances, fake_snapshot_instances)

    @ddt.data([constants.STATUS_ERROR, constants.STATUS_ACTIVE],
              [constants.STATUS_ACTIVE, constants.STATUS_ACTIVE])
    def test__check_share_network_update_finished(self, server_statuses):
        share_servers = [
            db_utils.create_share_server(status=status)
            for status in server_statuses]
        share_network = db_utils.create_share_network(
            status=constants.STATUS_SERVER_NETWORK_CHANGE)
        all_servers_are_active = (
            all(server_statuses) == constants.STATUS_ACTIVE)

        self.mock_object(db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(
            db, 'share_server_get_all_with_filters',
            mock.Mock(return_value=share_servers))
        self.mock_object(db, 'share_network_update')

        self.share_manager._check_share_network_update_finished(
            self.context, share_network['id'])

        db.share_server_get_all_with_filters.assert_called_once_with(
            self.context, {'share_network_id': share_network['id']})
        db.share_network_get.assert_called_once_with(
            self.context, share_network['id'])
        if all_servers_are_active:
            db.share_network_update.assert_called_once_with(
                self.context, share_network['id'],
                {'status': constants.STATUS_NETWORK_ACTIVE})

    def test__check_share_network_update_finished_already_active(self):
        share_network = db_utils.create_share_network()

        self.mock_object(db, 'share_network_get',
                         mock.Mock(return_value=share_network))
        self.mock_object(db, 'share_server_get_all_with_filters')

        self.share_manager._check_share_network_update_finished(
            self.context, share_network['id'])

        db.share_network_get.assert_called_once_with(
            self.context, share_network['id'])
        db.share_server_get_all_with_filters.assert_not_called()

    def _setup_mocks_for_sec_service_update(
            self, service_get_effect, share_network, share_servers, subnet,
            network_info, share_instances, fake_rules,
            driver_support_update=True, driver_update_action=mock.Mock()):

        self.mock_object(
            db, 'security_service_get',
            mock.Mock(side_effect=service_get_effect))
        self.mock_object(
            db, 'share_network_get',
            mock.Mock(return_value=share_network))
        self.mock_object(
            db, 'share_server_get_all_by_host',
            mock.Mock(return_value=share_servers))
        self.mock_object(
            db, 'share_network_subnet_get_all_by_share_server_id',
            mock.Mock(return_value=[subnet]))
        self.mock_object(
            self.share_manager, '_form_server_setup_info',
            mock.Mock(return_value=network_info))
        self.mock_object(
            db, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=share_instances))
        self.mock_object(
            db, 'share_access_get_all_for_instance',
            mock.Mock(return_value=fake_rules))
        self.mock_object(
            self.share_manager.driver,
            'check_update_share_server_security_service',
            mock.Mock(return_value=driver_support_update))
        self.mock_object(db, 'share_server_backend_details_set')
        self.mock_object(
            self.share_manager.driver,
            'update_share_server_security_service', driver_update_action)
        self.mock_object(db, 'share_server_update')
        self.mock_object(
            self.share_manager, '_check_share_network_update_finished')
        self.mock_object(
            self.share_manager.access_helper,
            'get_and_update_share_instance_access_rules')
        self.mock_object(
            self.share_manager.access_helper,
            'update_share_instances_access_rules_status')
        self.mock_object(
            self.share_manager.access_helper, 'process_driver_rule_updates')

    @ddt.data(False, True)
    def test__update_share_network_security_service(self, is_check_only):
        security_services = [
            db_utils.create_security_service() for i in range(2)]
        share_network = db_utils.create_share_network()
        share_network_subnet = db_utils.create_share_network_subnet()
        share_servers = [
            db_utils.create_share_server(
                share_network_subnets=[share_network_subnet])]
        security_services_effect = mock.Mock(side_effect=security_services)
        share_network_id = share_network['id']
        current_security_service_id = security_services[0]['id']
        new_security_service_id = security_services[1]['id']
        share_instances = [db_utils.create_share()['instance']]
        fake_rules = ['fake_rules']
        network_info = {'fake': 'fake'}
        backend_details_keys = [
            'name', 'ou', 'default_ad_site', 'domain', 'server', 'dns_ip',
            'user', 'type', 'password']
        backend_details_data = {}
        [backend_details_data.update(
            {key: security_services[0][key]}) for key in backend_details_keys]
        backend_details_exp_update = {
            'security_service_' + security_services[0]['type']:
                jsonutils.dumps(backend_details_data)
        }
        expected_instance_rules = [{
            'share_instance_id': share_instances[0]['id'],
            'access_rules': fake_rules
        }]
        rule_updates = {
            share_instances[0]['id']: {
                'access_rule_id': {
                    'access_key': 'fake_access_key',
                    'state': 'active',
                },
            },

        }
        expected_rule_updates_value = rule_updates[share_instances[0]['id']]
        driver_return = mock.Mock(return_value=rule_updates)

        self._setup_mocks_for_sec_service_update(
            security_services_effect, share_network, share_servers,
            share_network_subnet, network_info, share_instances, fake_rules,
            driver_update_action=driver_return)

        result = self.share_manager._update_share_network_security_service(
            self.context, share_network_id, new_security_service_id,
            current_security_service_id=current_security_service_id,
            check_only=is_check_only)

        db.security_service_get.assert_has_calls(
            [mock.call(self.context, security_services[1]['id']),
             mock.call(self.context, security_services[0]['id'])]
        )
        db.share_network_get.assert_called_once_with(
            self.context, share_network_id)
        db.share_server_get_all_by_host.assert_called_once_with(
            self.context, self.share_manager.host,
            filters={'share_network_id': share_network_id})
        (db.share_network_subnet_get_all_by_share_server_id.
            assert_called_once_with(
                self.context, share_servers[0]['id']))
        self.share_manager._form_server_setup_info.assert_called_once_with(
            self.context, share_servers[0], share_network,
            [share_network_subnet]
        )
        db.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, share_servers[0]['id'], with_share_data=True)
        db.share_access_get_all_for_instance.assert_called_once_with(
            self.context, share_instances[0]['id'])
        if not is_check_only:
            (self.share_manager.driver.update_share_server_security_service.
                assert_called_once_with(
                    self.context, share_servers[0], network_info,
                    share_instances,
                    expected_instance_rules,
                    security_services[0],
                    current_security_service=security_services[1]))
            db.share_server_backend_details_set.assert_called_once_with(
                self.context, share_servers[0]['id'],
                backend_details_exp_update)
            db.share_server_update.assert_called_once_with(
                self.context, share_servers[0]['id'],
                {'status': constants.STATUS_ACTIVE})
            (self.share_manager.access_helper.process_driver_rule_updates.
                assert_called_once_with(
                    self.context, expected_rule_updates_value,
                    share_instances[0]['id']))
        else:
            (self.share_manager.driver.
                check_update_share_server_security_service.
                assert_called_once_with(
                    self.context, share_servers[0], network_info,
                    share_instances,
                    expected_instance_rules,
                    security_services[0],
                    current_security_service=security_services[1]))
            self.assertEqual(result, True)

    def test__update_share_network_security_service_no_support(self):
        security_services = [
            db_utils.create_security_service() for i in range(2)]
        share_network = db_utils.create_share_network()
        share_network_subnet = db_utils.create_share_network_subnet()
        share_servers = [
            db_utils.create_share_server(
                share_network_subnets=[share_network_subnet])]
        security_services_effect = mock.Mock(side_effect=security_services)
        share_network_id = share_network['id']
        current_security_service_id = security_services[0]['id']
        new_security_service_id = security_services[1]['id']
        network_info = [{'fake': 'fake'}]
        share_instances = [db_utils.create_share()['instance']]
        fake_rules = ['fake_rules']
        expected_instance_rules = [{
            'share_instance_id': share_instances[0]['id'],
            'access_rules': fake_rules
        }]

        self._setup_mocks_for_sec_service_update(
            security_services_effect, share_network, share_servers,
            share_network_subnet, network_info, share_instances, fake_rules,
            driver_support_update=False)

        result = self.share_manager._update_share_network_security_service(
            self.context, share_network_id, new_security_service_id,
            current_security_service_id=current_security_service_id,
            check_only=True)

        db.security_service_get.assert_has_calls(
            [mock.call(self.context, security_services[1]['id']),
             mock.call(self.context, security_services[0]['id'])]
        )
        db.share_network_get.assert_called_once_with(
            self.context, share_network_id)
        db.share_server_get_all_by_host.assert_called_once_with(
            self.context, self.share_manager.host,
            filters={'share_network_id': share_network_id})
        (db.share_network_subnet_get_all_by_share_server_id.
         assert_called_once_with(self.context, share_servers[0]['id']))
        self.share_manager._form_server_setup_info.assert_called_once_with(
            self.context, share_servers[0], share_network,
            [share_network_subnet]
        )
        db.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, share_servers[0]['id'], with_share_data=True)
        db.share_access_get_all_for_instance.assert_called_once_with(
            self.context, share_instances[0]['id'])
        (self.share_manager.driver.check_update_share_server_security_service.
            assert_called_once_with(
                self.context, share_servers[0], network_info,
                share_instances,
                expected_instance_rules,
                security_services[0],
                current_security_service=security_services[1]))
        self.assertEqual(result, False)

    def test__update_share_network_security_service_exception(self):
        security_services = [
            db_utils.create_security_service() for i in range(2)]
        share_network = db_utils.create_share_network()
        share_network_subnet = db_utils.create_share_network_subnet()
        share_servers = [
            db_utils.create_share_server(
                share_network_subnets=[share_network_subnet])]
        share_instances = [db_utils.create_share_instance(share_id='fake')]
        share_instance_ids = [instance['id'] for instance in share_instances]
        security_services_effect = mock.Mock(side_effect=security_services)
        share_network_id = share_network['id']
        current_security_service_id = security_services[0]['id']
        new_security_service_id = security_services[1]['id']
        network_info = [{'fake': 'fake'}]
        backend_details_keys = [
            'name', 'ou', 'default_ad_site', 'domain', 'server', 'dns_ip',
            'user', 'type', 'password']
        backend_details_data = {}
        [backend_details_data.update(
            {key: security_services[0][key]}) for key in backend_details_keys]
        backend_details_exp_update = {
            'security_service_' + security_services[0]['type']:
                jsonutils.dumps(backend_details_data)
        }
        driver_exception = mock.Mock(side_effect=Exception())
        share_instances = [db_utils.create_share()['instance']]
        fake_rules = ['fake_rules']
        expected_instance_rules = [{
            'share_instance_id': share_instances[0]['id'],
            'access_rules': fake_rules
        }]

        self._setup_mocks_for_sec_service_update(
            security_services_effect, share_network, share_servers,
            share_network_subnet, network_info, share_instances, fake_rules,
            driver_update_action=driver_exception)

        self.mock_object(
            self.share_manager.access_helper,
            'update_share_instances_access_rules_status')
        self.mock_object(
            db, 'share_instances_get_all_by_share_server',
            mock.Mock(return_value=share_instances))

        self.share_manager._update_share_network_security_service(
            self.context, share_network_id, new_security_service_id,
            current_security_service_id=current_security_service_id)

        db.security_service_get.assert_has_calls(
            [mock.call(self.context, security_services[1]['id']),
             mock.call(self.context, security_services[0]['id'])]
        )
        db.share_network_get.assert_called_once_with(
            self.context, share_network_id)
        db.share_server_get_all_by_host.assert_called_once_with(
            self.context, self.share_manager.host,
            filters={'share_network_id': share_network_id})
        (db.share_network_subnet_get_all_by_share_server_id.
         assert_called_once_with(self.context, share_servers[0]['id']))
        self.share_manager._form_server_setup_info.assert_called_once_with(
            self.context, share_servers[0], share_network,
            [share_network_subnet]
        )
        (self.share_manager.driver.update_share_server_security_service.
            assert_called_once_with(
                self.context, share_servers[0], network_info,
                share_instances,
                expected_instance_rules,
                security_services[0],
                current_security_service=security_services[1]))
        db.share_server_backend_details_set.assert_called_once_with(
            self.context, share_servers[0]['id'],
            backend_details_exp_update)
        db.share_server_update.assert_called_once_with(
            self.context, share_servers[0]['id'],
            {'status': constants.STATUS_ERROR})
        db.share_instances_get_all_by_share_server.assert_called_once_with(
            self.context, share_servers[0]['id'], with_share_data=True)
        db.share_access_get_all_for_instance.assert_called_once_with(
            self.context, share_instances[0]['id'])
        (self.share_manager.access_helper.
            update_share_instances_access_rules_status(
                self.context, constants.SHARE_INSTANCE_RULES_ERROR,
                share_instance_ids))
        (self.share_manager.access_helper.
            get_and_update_share_instance_access_rules(
                self.context, updates={'state': constants.STATUS_ERROR},
                share_instance_id=share_instances[0]['id']))

    def test_update_share_network_security_service(self):
        share_network_id = 'fake_sn_id'
        new_security_service_id = 'new_sec_service_id'
        current_security_service_id = 'current_sec_service_id'

        self.mock_object(
            self.share_manager, '_update_share_network_security_service')

        self.share_manager.update_share_network_security_service(
            self.context, share_network_id, new_security_service_id,
            current_security_service_id=current_security_service_id)
        (self.share_manager._update_share_network_security_service.
            assert_called_once_with(
                self.context, share_network_id, new_security_service_id,
                current_security_service_id=current_security_service_id,
                check_only=False))

    def test_check_update_share_network_security_service(self):
        share_network_id = 'fake_sn_id'
        new_security_service_id = 'new_sec_service_id'
        current_security_service_id = 'current_sec_service_id'

        self.mock_object(
            self.share_manager, '_update_share_network_security_service')

        self.share_manager.check_update_share_network_security_service(
            self.context, share_network_id, new_security_service_id,
            current_security_service_id=current_security_service_id)
        (self.share_manager._update_share_network_security_service.
            assert_called_once_with(
                self.context, share_network_id, new_security_service_id,
                current_security_service_id=current_security_service_id,
                check_only=True))

    @ddt.data(None, '{"fake_host": false}')
    def test__update_share_server_allocations_check_operation(
            self, current_hosts_info):
        update_key = 'fake_key'
        mock_get_allocations_key = self.mock_object(
            self.share_manager.share_api,
            'get_share_server_update_allocations_key',
            mock.Mock(return_value=update_key))
        mock_get_data = self.mock_object(
            self.share_manager.db,
            'async_operation_data_get',
            mock.Mock(return_value=current_hosts_info))
        mock_update_data = self.mock_object(
            self.share_manager.db,
            'async_operation_data_update')

        share_network_id = 'fake_net_id'
        availability_zone_id = 'fake_az_id'
        self.share_manager._update_share_server_allocations_check_operation(
            self.context, True, share_network_id=share_network_id,
            availability_zone_id=availability_zone_id)

        mock_get_allocations_key.assert_called_once_with(
            share_network_id, availability_zone_id)
        mock_get_data.assert_called_once_with(
            self.context, share_network_id, update_key)
        if current_hosts_info:
            mock_update_data.assert_called_once_with(
                self.context, share_network_id,
                {update_key: json.dumps({self.share_manager.host: True})})
        else:
            mock_update_data.assert_not_called()

    def test__get_subnet_allocations(self):

        fake_allocations = ['fake_alloc']
        mock_get_allocations = self.mock_object(
            self.share_manager.db, 'network_allocations_get_for_share_server',
            mock.Mock(return_value=fake_allocations))
        subnet_id = 'fake_id'
        neutron_net_id = 'fake_net_id'
        neutron_subnet_id = 'fake_subnet_id'

        fake_subnet = {
            'id': subnet_id,
            'neutron_net_id': neutron_net_id,
            'neutron_subnet_id': neutron_subnet_id,
        }
        result = self.share_manager._get_subnet_allocations(
            self.context, 'fake_id', fake_subnet)

        expected_allocations = {
            'share_network_subnet_id': subnet_id,
            'neutron_net_id': neutron_net_id,
            'neutron_subnet_id': neutron_subnet_id,
            'network_allocations': fake_allocations,
        }
        self.assertEqual(expected_allocations, result)
        mock_get_allocations.assert_called_once_with(
            self.context, 'fake_id', label='user', subnet_id=fake_subnet['id'])

    def test__form_network_allocations(self):
        fake_allocation = 'fake_alloc'
        mock_get_allocations = self.mock_object(
            self.share_manager, '_get_subnet_allocations',
            mock.Mock(return_value=fake_allocation))
        mock_admin_allocations = self.mock_object(
            self.share_manager.db, 'network_allocations_get_for_share_server',
            mock.Mock(return_value=[fake_allocation]))

        result = self.share_manager._form_network_allocations(
            self.context, 'fake_id', ['fake_subnet'])

        expected_allocations = {
            'admin_network_allocations': [fake_allocation],
            'subnets': [fake_allocation],
        }
        self.assertEqual(expected_allocations, result)
        mock_get_allocations.assert_called_once_with(
            self.context, 'fake_id', 'fake_subnet')
        mock_admin_allocations.assert_called_once_with(
            self.context, 'fake_id', label='admin')

    @ddt.data(True, False)
    def test_check_update_share_server_network_allocations(self, support):
        security_services = 'fake_service'
        mock_net_get = self.mock_object(
            self.share_manager.db, 'share_network_get',
            mock.Mock(return_value={'security_services': security_services}))
        server = {'id': 'fake_id'}
        subnets = [{'share_servers': [server]}]
        mock_subnet_get = self.mock_object(
            self.share_manager.db,
            'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=subnets))
        mock_include_net_info = self.mock_object(
            self.share_manager.driver.network_api, 'include_network_info')
        current_network_allocations = 'fake_net_allocations'
        mock_form_net_allocations = self.mock_object(
            self.share_manager,
            '_form_network_allocations',
            mock.Mock(return_value=current_network_allocations))
        share_id = 'fake_id'
        shares = [fakes.fake_share(id=share_id)]
        mock_shares_get = self.mock_object(
            self.share_manager.db,
            'share_instances_get_all_by_share_server',
            mock.Mock(return_value=shares))
        access = 'fake_access'
        mock_access_get = self.mock_object(
            self.share_manager.db,
            'share_access_get_all_for_instance',
            mock.Mock(return_value=access))
        mock_check_update = self.mock_object(
            self.share_manager.driver,
            'check_update_share_server_network_allocations',
            mock.Mock(return_value=support))
        mock_update_check_operation = self.mock_object(
            self.share_manager,
            '_update_share_server_allocations_check_operation')

        new_subnet = {'availability_zone_id': 'fake_az'}
        net_id = 'fake_net_id'
        self.share_manager.check_update_share_server_network_allocations(
            self.context, net_id, new_subnet)

        mock_net_get.assert_called_once_with(self.context, net_id)
        mock_subnet_get.assert_called_once_with(
            self.context, net_id, new_subnet['availability_zone_id'],
            fallback_to_default=False)
        mock_include_net_info.assert_called_once_with(new_subnet)
        mock_form_net_allocations.assert_called_once_with(
            self.context, server['id'], subnets)
        mock_shares_get.assert_called_once_with(
            self.context, server['id'], with_share_data=True)
        mock_access_get.assert_called_once_with(self.context, share_id)
        access_list = [{'share_instance_id': share_id, 'access_rules': access}]
        mock_check_update.assert_called_once_with(
            self.context, server, current_network_allocations,
            new_subnet, security_services, shares, access_list)
        mock_update_check_operation.assert_called_once_with(
            self.context, support, share_network_id=net_id,
            availability_zone_id=new_subnet['availability_zone_id'])

    def test__do_update_share_server_network_allocations(self):
        mock_allocate = self.mock_object(
            self.share_manager.driver, 'allocate_network')
        net_allocations = {'network_allocations': ['fake_allocation']}
        mock_get_allocations = self.mock_object(
            self.share_manager, '_get_subnet_allocations',
            mock.Mock(return_value=net_allocations))
        mock_validate_segmentation = self.mock_object(
            self.share_manager, '_validate_segmentation_id')
        server_details = 'fake_details'
        snap_export = [{'path': 'fake_path', 'is_admin_only': 'fake_is_admin'}]
        update_model = {
            'server_details': server_details,
            'share_updates': {'fake_id': 'fake_export'},
            'snapshot_updates': {
                'fake_id': {
                    'export_locations': snap_export,
                    'status': 'fake_status',
                },
            },
        }
        mock_update_server_allocations = self.mock_object(
            self.share_manager.driver,
            'update_share_server_network_allocations',
            mock.Mock(return_value=update_model))
        mock_update_net_allocation = self.mock_object(
            self.share_manager.driver, 'update_network_allocation')
        mock_db_backend_details_set = self.mock_object(
            self.share_manager.db, 'share_server_backend_details_set')
        mock_db_export_share_update = self.mock_object(
            self.share_manager.db, 'share_export_locations_update')
        mock_db_snapshot_update = self.mock_object(
            self.share_manager.db, 'share_snapshot_instance_update')
        mock_db_export_snap_update = self.mock_object(
            self.share_manager.db,
            'share_snapshot_instance_export_locations_update')

        server = {'id': 'fake_id'}
        share_net = {'security_services': 'fake_services'}
        new_subnet = 'fake_subnet'
        current_network_allocations = 'fake_allocations'
        share_instances = 'fake_instances'
        snapshot_instance_ids = 'fake_snaps'
        self.share_manager._do_update_share_server_network_allocations(
            self.context, server, share_net, new_subnet,
            current_network_allocations, share_instances, snapshot_instance_ids
        )

        mock_update_server_allocations.assert_called_once_with(
            self.context, server, current_network_allocations,
            net_allocations, share_net['security_services'], share_instances,
            snapshot_instance_ids)
        mock_allocate.assert_called_once_with(
            self.context, server, share_net, new_subnet)
        mock_get_allocations.assert_called_once_with(
            self.context, server['id'], new_subnet)
        mock_validate_segmentation.assert_called_once_with(
            net_allocations['network_allocations'][0])
        mock_update_net_allocation.assert_called_once_with(
            self.context, server)
        mock_db_backend_details_set.assert_called_once_with(
            self.context, server['id'], server_details)
        mock_db_export_share_update.assert_called_once_with(
            self.context, 'fake_id', 'fake_export')
        mock_db_snapshot_update.assert_called_once_with(
            self.context, 'fake_id', {'status': 'fake_status'})
        mock_db_export_snap_update.assert_called_once_with(
            self.context, 'fake_id', snap_export)

    def test__do_update_share_server_network_allocations_exception(self):
        self.mock_object(self.share_manager.driver, 'allocate_network')
        net_allocations = {'network_allocations': []}
        self.mock_object(
            self.share_manager, '_get_subnet_allocations',
            mock.Mock(return_value=net_allocations))
        server = {'id': 'fake_id'}
        share_net = {'security_services': 'fake_services'}
        new_subnet = 'fake_subnet'
        current_network_allocations = 'fake_allocations'
        share_instances = 'fake_instances'
        snapshot_instance_ids = 'fake_snaps'

        self.assertRaises(
            exception.AllocationsNotFoundForShareServer,
            self.share_manager._do_update_share_server_network_allocations,
            self.context, server, share_net, new_subnet,
            current_network_allocations, share_instances, snapshot_instance_ids
        )

    def test_update_share_server_network_allocations(self):
        net_id = 'fake_net_id'
        mock_net_get = self.mock_object(
            self.share_manager.db, 'share_network_get',
            mock.Mock(return_value={'id': net_id}))
        new_subnet = {'availability_zone_id': 'fake_id'}
        mock_subnet_get = self.mock_object(
            self.share_manager.db, 'share_network_subnet_get',
            mock.Mock(return_value=new_subnet))
        subnets = [{'id': 'fake_id'}]
        mock_subnets_get = self.mock_object(
            self.share_manager.db,
            'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=subnets))
        server_id = 'fake_server_id'
        server = {'id': server_id}
        mock_servers_get = self.mock_object(
            self.share_manager.db,
            'share_server_get_all_by_host_and_share_subnet',
            mock.Mock(return_value=[server]))
        current_network_allocations = 'fake_current_net_allocations'
        mock_form_net_allocations = self.mock_object(
            self.share_manager, '_form_network_allocations',
            mock.Mock(return_value=current_network_allocations))
        share_instances = [{'id': 'fake_id'}]
        mock_instances_get = self.mock_object(
            self.share_manager.db,
            'share_instances_get_all_by_share_server',
            mock.Mock(return_value=share_instances))
        snap_instances = [{'id': 'fake_id'}]
        mock_snap_instances_get = self.mock_object(
            self.share_manager.db,
            'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=snap_instances))
        mock_do_update = self.mock_object(
            self.share_manager, '_do_update_share_server_network_allocations')
        mock_server_update = self.mock_object(
            self.share_manager.db,
            'share_server_update',
            mock.Mock(return_value=snap_instances))
        mock_check_update_finished = self.mock_object(
            self.share_manager, '_check_share_network_update_finished')

        new_share_network_subnet_id = 'fake_new_subnet_id'
        self.share_manager.update_share_server_network_allocations(
            self.context, net_id, new_share_network_subnet_id)

        mock_net_get.assert_called_once_with(self.context, net_id)
        mock_subnet_get.assert_called_once_with(self.context,
                                                new_share_network_subnet_id)
        mock_subnets_get.assert_called_once_with(
            self.context, net_id, new_subnet['availability_zone_id'],
            fallback_to_default=False)
        mock_servers_get.assert_called_once_with(
            self.context, self.share_manager.host, new_share_network_subnet_id)
        mock_form_net_allocations.assert_called_once_with(
            self.context, server['id'], subnets)
        mock_instances_get.assert_called_once_with(
            self.context, server['id'], with_share_data=True)
        mock_snap_instances_get.assert_called_once_with(
            self.context, {'share_instance_ids': ['fake_id']})
        mock_do_update.assert_called_once_with(
            self.context, server, {'id': net_id}, new_subnet,
            current_network_allocations, share_instances,
            snap_instances)
        mock_server_update.assert_called_once_with(
            self.context, server['id'], {'status': constants.STATUS_ACTIVE})
        mock_check_update_finished.assert_called_once_with(
            self.context, share_network_id=net_id)

    def test_update_share_server_network_allocations_failed(self):
        net_id = 'fake_net_id'
        mock_net_get = self.mock_object(
            self.share_manager.db, 'share_network_get',
            mock.Mock(return_value={'id': net_id}))
        new_subnet = {'availability_zone_id': 'fake_id'}
        mock_subnet_get = self.mock_object(
            self.share_manager.db, 'share_network_subnet_get',
            mock.Mock(return_value=new_subnet))
        subnets = [{'id': 'fake_id'}]
        mock_subnets_get = self.mock_object(
            self.share_manager.db,
            'share_network_subnets_get_all_by_availability_zone_id',
            mock.Mock(return_value=subnets))
        server_id = 'fake_server_id'
        server = {'id': server_id}
        mock_servers_get = self.mock_object(
            self.share_manager.db,
            'share_server_get_all_by_host_and_share_subnet',
            mock.Mock(return_value=[server]))
        current_network_allocations = 'fake_current_net_allocations'
        mock_form_net_allocations = self.mock_object(
            self.share_manager, '_form_network_allocations',
            mock.Mock(return_value=current_network_allocations))
        share_instances = [{'id': 'fake_id'}]
        mock_instances_get = self.mock_object(
            self.share_manager.db,
            'share_instances_get_all_by_share_server',
            mock.Mock(return_value=share_instances))
        snap_instances = [{'id': 'fake_id'}]
        mock_snap_instances_get = self.mock_object(
            self.share_manager.db,
            'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=snap_instances))
        mock_do_update = self.mock_object(
            self.share_manager, '_do_update_share_server_network_allocations',
            mock.Mock(side_effect=exception.AllocationsNotFoundForShareServer(
                share_server_id=server_id)))
        mock_handle_error = self.mock_object(
            self.share_manager, '_handle_setup_server_error')
        mock_update_status = self.mock_object(
            self.share_manager, '_update_resource_status')
        mock_server_update = self.mock_object(
            self.share_manager.db,
            'share_server_update',
            mock.Mock(return_value=snap_instances))
        mock_check_update_finished = self.mock_object(
            self.share_manager, '_check_share_network_update_finished')

        new_share_network_subnet_id = 'fake_new_subnet_id'
        self.share_manager.update_share_server_network_allocations(
            self.context, net_id, new_share_network_subnet_id)

        mock_net_get.assert_called_once_with(self.context, net_id)
        mock_subnet_get.assert_called_once_with(self.context,
                                                new_share_network_subnet_id)
        mock_subnets_get.assert_called_once_with(
            self.context, net_id, new_subnet['availability_zone_id'],
            fallback_to_default=False)
        mock_servers_get.assert_called_once_with(
            self.context, self.share_manager.host, new_share_network_subnet_id)
        mock_form_net_allocations.assert_called_once_with(
            self.context, server['id'], subnets)
        mock_instances_get.assert_called_once_with(
            self.context, server['id'], with_share_data=True)
        mock_snap_instances_get.assert_called_once_with(
            self.context, {'share_instance_ids': ['fake_id']})
        mock_do_update.assert_called_once_with(
            self.context, server, {'id': net_id}, new_subnet,
            current_network_allocations, share_instances,
            snap_instances)
        mock_server_update.assert_not_called()
        mock_handle_error.assert_called()
        mock_update_status.assert_called_once_with(
            self.context, constants.STATUS_ERROR,
            share_instance_ids=['fake_id'], snapshot_instance_ids=['fake_id'])
        mock_check_update_finished.assert_called_once_with(
            self.context, share_network_id=net_id)


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
