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
Tests For Base Scheduler
"""

import mock
from oslo_config import cfg
from oslo_utils import timeutils

from manila import context
from manila import db
from manila.scheduler.drivers import base
from manila import test
from manila import utils

CONF = cfg.CONF


class SchedulerTestCase(test.TestCase):
    """Test case for base scheduler driver class."""

    # So we can subclass this test and re-use tests if we need.
    driver_cls = base.Scheduler

    def setUp(self):
        super(SchedulerTestCase, self).setUp()
        self.driver = self.driver_cls()
        self.context = context.RequestContext('fake_user', 'fake_project')
        self.topic = 'fake_topic'

    def test_update_service_capabilities(self):
        service_name = 'fake_service'
        host = 'fake_host'
        capabilities = {'fake_capability': 'fake_value'}
        with mock.patch.object(self.driver.host_manager,
                               'update_service_capabilities', mock.Mock()):
            self.driver.update_service_capabilities(
                service_name, host, capabilities)
            (self.driver.host_manager.update_service_capabilities.
                assert_called_once_with(service_name, host, capabilities))

    def test_hosts_up(self):
        service1 = {'host': 'host1'}
        service2 = {'host': 'host2'}
        services = [service1, service2]

        def fake_service_is_up(*args, **kwargs):
            if args[0]['host'] == 'host1':
                return False
            return True

        with mock.patch.object(db, 'service_get_all_by_topic',
                               mock.Mock(return_value=services)):
            with mock.patch.object(utils, 'service_is_up',
                                   mock.Mock(side_effect=fake_service_is_up)):
                result = self.driver.hosts_up(self.context, self.topic)
                self.assertEqual(['host2'], result)
                db.service_get_all_by_topic.assert_called_once_with(
                    self.context, self.topic)


class SchedulerDriverBaseTestCase(SchedulerTestCase):
    """Test cases for base scheduler driver class methods.

    These can't fail if the driver is changed.
    """

    def test_unimplemented_schedule(self):
        fake_args = (1, 2, 3)
        fake_kwargs = {'cat': 'meow'}

        self.assertRaises(NotImplementedError, self.driver.schedule,
                          self.context, self.topic, 'schedule_something',
                          *fake_args, **fake_kwargs)


class SchedulerDriverModuleTestCase(test.TestCase):
    """Test case for scheduler driver module methods."""

    def setUp(self):
        super(SchedulerDriverModuleTestCase, self).setUp()
        self.context = context.RequestContext('fake_user', 'fake_project')

    @mock.patch.object(db, 'share_update', mock.Mock())
    def test_share_host_update_db(self):
        with mock.patch.object(timeutils, 'utcnow',
                               mock.Mock(return_value='fake-now')):
            base.share_update_db(self.context, 31337, 'fake_host')
            db.share_update.assert_called_once_with(
                self.context, 31337,
                {'host': 'fake_host', 'scheduled_at': 'fake-now'})
