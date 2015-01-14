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

import mock
from oslo_utils import importutils

from manila import manager
from manila import test


class ManagerTestCase(test.TestCase):

    @mock.patch.object(importutils, 'import_module', mock.Mock())
    def test_verify_manager_instance(self):
        host = 'fake_host'
        db_driver = 'fake_driver'
        fake_manager = manager.Manager(host, db_driver)
        self.assertTrue(hasattr(fake_manager, '_periodic_tasks'))
        self.assertTrue(hasattr(fake_manager, '_ticks_to_skip'))
        self.assertTrue(hasattr(fake_manager, 'additional_endpoints'))
        self.assertTrue(hasattr(fake_manager, 'host'))
        self.assertTrue(hasattr(fake_manager, 'periodic_tasks'))
        self.assertTrue(hasattr(fake_manager, 'init_host'))
        self.assertTrue(hasattr(fake_manager, 'service_version'))
        self.assertTrue(hasattr(fake_manager, 'service_config'))
        self.assertEqual(fake_manager.host, host)
        importutils.import_module.assert_called_once_with(db_driver)


class SchedulerDependentManagerTestCase(test.TestCase):

    @mock.patch.object(importutils, 'import_module', mock.Mock())
    def test_verify_scheduler_dependent_manager_instance(self):
        host = 'fake_host'
        db_driver = 'fake_driver'
        service_name = 'fake_service_name'
        fake_sched_manager = manager.SchedulerDependentManager(
            host, db_driver, service_name)
        self.assertTrue(hasattr(fake_sched_manager, '_periodic_tasks'))
        self.assertTrue(hasattr(fake_sched_manager, '_ticks_to_skip'))
        self.assertTrue(hasattr(fake_sched_manager, 'additional_endpoints'))
        self.assertTrue(hasattr(fake_sched_manager, 'host'))
        self.assertTrue(hasattr(fake_sched_manager, 'periodic_tasks'))
        self.assertTrue(hasattr(fake_sched_manager, 'init_host'))
        self.assertTrue(hasattr(fake_sched_manager, 'service_version'))
        self.assertTrue(hasattr(fake_sched_manager, 'service_config'))
        self.assertTrue(hasattr(fake_sched_manager, 'last_capabilities'))
        self.assertTrue(hasattr(fake_sched_manager, 'service_name'))
        self.assertTrue(hasattr(fake_sched_manager, 'scheduler_rpcapi'))
        self.assertTrue(hasattr(fake_sched_manager,
                                'update_service_capabilities'))
        self.assertTrue(hasattr(fake_sched_manager,
                                '_publish_service_capabilities'))
        self.assertEqual(fake_sched_manager.host, host)
        self.assertEqual(fake_sched_manager.service_name, service_name)
        importutils.import_module.assert_called_once_with(db_driver)
