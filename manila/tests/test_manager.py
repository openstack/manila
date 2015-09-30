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

"""Test of Base Manager for Manila."""

import ddt
import mock
from oslo_utils import importutils

from manila import manager
from manila import test


@ddt.ddt
class ManagerTestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.host = 'host'
        self.db_driver = 'fake_driver'
        self.mock_object(importutils, 'import_module')

    def test_verify_manager_instance(self):
        fake_manager = manager.Manager(self.host, self.db_driver)
        self.assertTrue(hasattr(fake_manager, '_periodic_tasks'))
        self.assertTrue(hasattr(fake_manager, 'additional_endpoints'))
        self.assertTrue(hasattr(fake_manager, 'host'))
        self.assertTrue(hasattr(fake_manager, 'periodic_tasks'))
        self.assertTrue(hasattr(fake_manager, 'init_host'))
        self.assertTrue(hasattr(fake_manager, 'service_version'))
        self.assertTrue(hasattr(fake_manager, 'service_config'))
        self.assertEqual(self.host, fake_manager.host)
        importutils.import_module.assert_called_once_with(self.db_driver)

    @ddt.data(True, False)
    def test_periodic_tasks(self, raise_on_error):
        fake_manager = manager.Manager(self.host, self.db_driver)
        fake_context = 'fake_context'
        self.mock_object(fake_manager, 'run_periodic_tasks')

        fake_manager.periodic_tasks(fake_context, raise_on_error)

        fake_manager.run_periodic_tasks.assert_called_once_with(
            fake_context, raise_on_error=raise_on_error)


@ddt.ddt
class SchedulerDependentManagerTestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.context = 'fake_context'
        self.host = 'host'
        self.db_driver = 'fake_driver'
        self.service_name = 'fake_service_name'
        self.mock_object(importutils, 'import_module')
        self.sched_manager = manager.SchedulerDependentManager(
            self.host, self.db_driver, self.service_name)

    def test_verify_scheduler_dependent_manager_instance(self):
        self.assertTrue(hasattr(self.sched_manager, '_periodic_tasks'))
        self.assertTrue(hasattr(self.sched_manager, 'additional_endpoints'))
        self.assertTrue(hasattr(self.sched_manager, 'host'))
        self.assertTrue(hasattr(self.sched_manager, 'periodic_tasks'))
        self.assertTrue(hasattr(self.sched_manager, 'init_host'))
        self.assertTrue(hasattr(self.sched_manager, 'service_version'))
        self.assertTrue(hasattr(self.sched_manager, 'service_config'))
        self.assertTrue(hasattr(self.sched_manager, 'last_capabilities'))
        self.assertTrue(hasattr(self.sched_manager, 'service_name'))
        self.assertTrue(hasattr(self.sched_manager, 'scheduler_rpcapi'))
        self.assertTrue(hasattr(self.sched_manager,
                                'update_service_capabilities'))
        self.assertTrue(hasattr(self.sched_manager,
                                '_publish_service_capabilities'))
        self.assertEqual(self.host, self.sched_manager.host)
        self.assertEqual(self.service_name, self.sched_manager.service_name)
        importutils.import_module.assert_called_once_with(self.db_driver)

    @ddt.data(None, {}, [], '')
    def test__publish_service_capabilities_no_update(self, last_capabilities):
        self.sched_manager.last_capabilities = last_capabilities
        self.mock_object(
            self.sched_manager.scheduler_rpcapi, 'update_service_capabilities')

        self.sched_manager._publish_service_capabilities('fake_context')

        self.assertFalse(
            self.sched_manager.scheduler_rpcapi.update_service_capabilities.
            called)

    @ddt.data('fake_last_capabilities', {'foo': 'bar'})
    def test__publish_service_capabilities_with_update(self,
                                                       last_capabilities):
        self.sched_manager.last_capabilities = last_capabilities
        self.mock_object(
            self.sched_manager.scheduler_rpcapi, 'update_service_capabilities')
        self.mock_object(manager.LOG, 'debug')

        self.sched_manager._publish_service_capabilities(self.context)

        self.sched_manager.scheduler_rpcapi.update_service_capabilities.\
            assert_called_once_with(
                self.context, self.service_name, self.host, last_capabilities)
        manager.LOG.debug.assert_called_once_with(mock.ANY)

    @ddt.data(None, '', [], {}, {'foo': 'bar'})
    def test_update_service_capabilities(self, capabilities):
        self.sched_manager.update_service_capabilities(capabilities)
        self.assertEqual(capabilities, self.sched_manager.last_capabilities)
