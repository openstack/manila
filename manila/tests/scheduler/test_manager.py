# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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
Tests For Scheduler Manager
"""

import ddt
import mock
from oslo_config import cfg

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.scheduler.drivers import base
from manila.scheduler.drivers import filter
from manila.scheduler import manager
from manila.share import rpcapi as share_rpcapi
from manila import test
from manila.tests import db_utils
from manila.tests import fake_share as fakes

CONF = cfg.CONF


@ddt.ddt
class SchedulerManagerTestCase(test.TestCase):
    """Test case for scheduler manager."""

    manager_cls = manager.SchedulerManager
    driver_cls = base.Scheduler
    driver_cls_name = 'manila.scheduler.drivers.base.Scheduler'

    def setUp(self):
        super(SchedulerManagerTestCase, self).setUp()
        self.flags(scheduler_driver=self.driver_cls_name)
        self.manager = self.manager_cls()
        self.context = context.RequestContext('fake_user', 'fake_project')
        self.topic = 'fake_topic'
        self.fake_args = (1, 2, 3)
        self.fake_kwargs = {'cat': 'meow', 'dog': 'woof'}

    def raise_no_valid_host(*args, **kwargs):
            raise exception.NoValidHost(reason="")

    def test_1_correct_init(self):
        # Correct scheduler driver
        manager = self.manager
        self.assertIsInstance(manager.driver, self.driver_cls)

    @ddt.data('manila.scheduler.filter_scheduler.FilterScheduler',
              'manila.scheduler.drivers.filter.FilterScheduler')
    def test_scheduler_driver_mapper(self, driver_class):

        test_manager = manager.SchedulerManager(scheduler_driver=driver_class)

        self.assertIsInstance(test_manager.driver, filter.FilterScheduler)

    def test_init_host(self):

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        self.mock_object(self.manager, 'request_service_capabilities')

        self.manager.init_host()

        self.manager.request_service_capabilities.assert_called_once_with(
            'fake_admin_context')

    def test_get_host_list(self):

        self.mock_object(self.manager.driver, 'get_host_list')

        self.manager.get_host_list(context)

        self.manager.driver.get_host_list.assert_called_once_with()

    def test_get_service_capabilities(self):

        self.mock_object(self.manager.driver, 'get_service_capabilities')

        self.manager.get_service_capabilities(context)

        self.manager.driver.get_service_capabilities.assert_called_once_with()

    def test_update_service_capabilities(self):
        service_name = 'fake_service'
        host = 'fake_host'
        with mock.patch.object(self.manager.driver,
                               'update_service_capabilities', mock.Mock()):
            self.manager.update_service_capabilities(
                self.context, service_name=service_name, host=host)
            (self.manager.driver.update_service_capabilities.
                assert_called_once_with(service_name, host, {}))
        with mock.patch.object(self.manager.driver,
                               'update_service_capabilities', mock.Mock()):
            capabilities = {'fake_capability': 'fake_value'}
            self.manager.update_service_capabilities(
                self.context, service_name=service_name, host=host,
                capabilities=capabilities)
            (self.manager.driver.update_service_capabilities.
                assert_called_once_with(service_name, host, capabilities))

    @mock.patch.object(db, 'share_update', mock.Mock())
    def test_create_share_exception_puts_share_in_error_state(self):
        """Test NoValidHost exception for create_share.

        Puts the share in 'error' state and eats the exception.
        """
        fake_share_id = 1

        request_spec = {'share_id': fake_share_id}
        with mock.patch.object(
                self.manager.driver, 'schedule_create_share',
                mock.Mock(side_effect=self.raise_no_valid_host)):
            self.mock_object(manager.LOG, 'error')

            self.manager.create_share_instance(
                self.context, request_spec=request_spec, filter_properties={})

            db.share_update.assert_called_once_with(
                self.context, fake_share_id, {'status': 'error'})
            (self.manager.driver.schedule_create_share.
                assert_called_once_with(self.context, request_spec, {}))
            manager.LOG.error.assert_called_once_with(mock.ANY, mock.ANY)

    @mock.patch.object(db, 'share_update', mock.Mock())
    def test_create_share_other_exception_puts_share_in_error_state(self):
        """Test any exception except NoValidHost for create_share.

        Puts the share in 'error' state and re-raises the exception.
        """
        fake_share_id = 1

        request_spec = {'share_id': fake_share_id}
        with mock.patch.object(self.manager.driver,
                               'schedule_create_share',
                               mock.Mock(side_effect=exception.QuotaError)):
            self.mock_object(manager.LOG, 'error')

            self.assertRaises(exception.QuotaError,
                              self.manager.create_share_instance,
                              self.context,
                              request_spec=request_spec,
                              filter_properties={})

            db.share_update.assert_called_once_with(
                self.context, fake_share_id, {'status': 'error'})
            (self.manager.driver.schedule_create_share.
                assert_called_once_with(self.context, request_spec, {}))
            manager.LOG.error.assert_called_once_with(mock.ANY, mock.ANY)

    def test_get_pools(self):
        """Ensure get_pools exists and calls base_scheduler.get_pools."""
        mock_get_pools = self.mock_object(self.manager.driver,
                                          'get_pools',
                                          mock.Mock(return_value='fake_pools'))

        result = self.manager.get_pools(self.context, filters='fake_filters')

        mock_get_pools.assert_called_once_with(self.context, 'fake_filters')
        self.assertEqual('fake_pools', result)

    @mock.patch.object(db, 'consistency_group_update', mock.Mock())
    def test_create_cg_no_valid_host_puts_cg_in_error_state(self):
        """Test that NoValidHost is raised for create_consistency_group.

        Puts the share in 'error' state and eats the exception.
        """

        fake_cg_id = 1
        cg_id = fake_cg_id
        request_spec = {"consistency_group_id": cg_id}
        with mock.patch.object(
                self.manager.driver, 'schedule_create_consistency_group',
                mock.Mock(side_effect=self.raise_no_valid_host)):
            self.manager.create_consistency_group(self.context,
                                                  fake_cg_id,
                                                  request_spec=request_spec,
                                                  filter_properties={})
            db.consistency_group_update.assert_called_once_with(
                self.context, fake_cg_id, {'status': 'error'})
            (self.manager.driver.schedule_create_consistency_group.
                assert_called_once_with(self.context, cg_id, request_spec, {}))

    @mock.patch.object(db, 'consistency_group_update', mock.Mock())
    def test_create_cg_exception_puts_cg_in_error_state(self):
        """Test that exceptions for create_consistency_group.

        Puts the share in 'error' state and raises the exception.
        """

        fake_cg_id = 1
        cg_id = fake_cg_id
        request_spec = {"consistency_group_id": cg_id}
        with mock.patch.object(self.manager.driver,
                               'schedule_create_consistency_group',
                               mock.Mock(side_effect=exception.NotFound)):
            self.assertRaises(exception.NotFound,
                              self.manager.create_consistency_group,
                              self.context, fake_cg_id,
                              request_spec=request_spec,
                              filter_properties={})

    def test_migrate_share_to_host(self):

        share = db_utils.create_share()
        host = 'fake@backend#pool'

        self.mock_object(db, 'share_get', mock.Mock(return_value=share))
        self.mock_object(share_rpcapi.ShareAPI, 'migration_start')
        self.mock_object(base.Scheduler,
                         'host_passes_filters',
                         mock.Mock(return_value=host))

        self.manager.migrate_share_to_host(self.context, share['id'], host,
                                           False, True, {}, None)

    def test_migrate_share_to_host_no_valid_host(self):

        share = db_utils.create_share()
        host = 'fake@backend#pool'

        self.mock_object(
            base.Scheduler, 'host_passes_filters',
            mock.Mock(side_effect=[exception.NoValidHost('fake')]))

        self.assertRaises(
            exception.NoValidHost, self.manager.migrate_share_to_host,
            self.context, share['id'], host, False, True, {}, None)

    def test_manage_share(self):

        share = db_utils.create_share()

        self.mock_object(db, 'share_get', mock.Mock(return_value=share))
        self.mock_object(share_rpcapi.ShareAPI, 'manage_share')
        self.mock_object(base.Scheduler, 'host_passes_filters')

        self.manager.manage_share(self.context, share['id'], 'driver_options',
                                  {}, None)

    def test_manage_share_exception(self):

        share = db_utils.create_share()

        self.mock_object(
            base.Scheduler, 'host_passes_filters',
            mock.Mock(side_effect=exception.NoValidHost('fake')))

        self.assertRaises(
            exception.NoValidHost, self.manager.manage_share,
            self.context, share['id'], 'driver_options', {}, None)

    def test_create_share_replica_exception_path(self):
        """Test 'raisable' exceptions for create_share_replica."""
        db_update = self.mock_object(db, 'share_replica_update')
        self.mock_object(db, 'share_snapshot_instance_get_all_with_filters',
                         mock.Mock(return_value=[{'id': '123'}]))
        snap_update = self.mock_object(db, 'share_snapshot_instance_update')
        request_spec = fakes.fake_replica_request_spec()
        replica_id = request_spec.get('share_instance_properties').get('id')
        expected_updates = {
            'status': constants.STATUS_ERROR,
            'replica_state': constants.STATUS_ERROR,
        }
        with mock.patch.object(self.manager.driver, 'schedule_create_replica',
                               mock.Mock(side_effect=exception.NotFound)):

            self.assertRaises(exception.NotFound,
                              self.manager.create_share_replica,
                              self.context,
                              request_spec=request_spec,
                              filter_properties={})
            db_update.assert_called_once_with(
                self.context, replica_id, expected_updates)
            snap_update.assert_called_once_with(
                self.context, '123', {'status': constants.STATUS_ERROR})

    def test_create_share_replica_no_valid_host(self):
        """Test the NoValidHost exception for create_share_replica."""
        db_update = self.mock_object(db, 'share_replica_update')
        request_spec = fakes.fake_replica_request_spec()
        replica_id = request_spec.get('share_instance_properties').get('id')
        expected_updates = {
            'status': constants.STATUS_ERROR,
            'replica_state': constants.STATUS_ERROR,
        }
        with mock.patch.object(
                self.manager.driver, 'schedule_create_replica',
                mock.Mock(side_effect=self.raise_no_valid_host)):

            retval = self.manager.create_share_replica(
                self.context, request_spec=request_spec, filter_properties={})

            self.assertIsNone(retval)
            db_update.assert_called_once_with(
                self.context, replica_id, expected_updates)

    def test_create_share_replica(self):
        """Test happy path for create_share_replica."""
        db_update = self.mock_object(db, 'share_replica_update')
        mock_scheduler_driver_call = self.mock_object(
            self.manager.driver, 'schedule_create_replica')
        request_spec = fakes.fake_replica_request_spec()

        retval = self.manager.create_share_replica(
            self.context, request_spec=request_spec, filter_properties={})

        mock_scheduler_driver_call.assert_called_once_with(
            self.context, request_spec, {})
        self.assertFalse(db_update.called)
        self.assertIsNone(retval)
