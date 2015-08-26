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
Tests For Scheduler
"""

import mock
from oslo_config import cfg
from oslo_utils import timeutils

from manila import context
from manila import db
from manila import exception
from manila.scheduler import driver
from manila.scheduler import manager
from manila.scheduler import simple
from manila.share import rpcapi as share_rpcapi
from manila import test
from manila.tests import db_utils
from manila import utils

CONF = cfg.CONF


class SchedulerManagerTestCase(test.TestCase):
    """Test case for scheduler manager."""

    manager_cls = manager.SchedulerManager
    driver_cls = driver.Scheduler
    driver_cls_name = 'manila.scheduler.driver.Scheduler'

    def setUp(self):
        super(SchedulerManagerTestCase, self).setUp()
        self.flags(scheduler_driver=self.driver_cls_name)
        self.manager = self.manager_cls()
        self.context = context.RequestContext('fake_user', 'fake_project')
        self.topic = 'fake_topic'
        self.fake_args = (1, 2, 3)
        self.fake_kwargs = {'cat': 'meow', 'dog': 'woof'}

    def test_1_correct_init(self):
        # Correct scheduler driver
        manager = self.manager
        self.assertTrue(isinstance(manager.driver, self.driver_cls))

    def test_update_service_capabilities(self):
        service_name = 'fake_service'
        host = 'fake_host'
        with mock.patch.object(self.manager.driver,
                               'update_service_capabilities', mock.Mock()):
            self.manager.update_service_capabilities(
                self.context, service_name=service_name, host=host)
            self.manager.driver.update_service_capabilities.\
                assert_called_once_with(service_name, host, {})
        with mock.patch.object(self.manager.driver,
                               'update_service_capabilities', mock.Mock()):
            capabilities = {'fake_capability': 'fake_value'}
            self.manager.update_service_capabilities(
                self.context, service_name=service_name, host=host,
                capabilities=capabilities)
            self.manager.driver.update_service_capabilities.\
                assert_called_once_with(service_name, host, capabilities)

    @mock.patch.object(db, 'share_update', mock.Mock())
    def test_create_share_exception_puts_share_in_error_state(self):
        """Test that a NoValideHost exception for create_share.

        Puts the share in 'error' state and eats the exception.
        """
        def raise_no_valid_host(*args, **kwargs):
            raise exception.NoValidHost(reason="")

        fake_share_id = 1

        request_spec = {'share_id': fake_share_id}
        with mock.patch.object(self.manager.driver,
                               'schedule_create_share',
                               mock.Mock(side_effect=raise_no_valid_host)):
            self.mock_object(manager.LOG, 'error')
            self.manager.create_share_instance(
                self.context, request_spec=request_spec, filter_properties={})
            db.share_update.assert_called_once_with(
                self.context, fake_share_id, {'status': 'error'})
            self.manager.driver.schedule_create_share.assert_called_once_with(
                self.context, request_spec, {})
            manager.LOG.error.assert_called_once_with(mock.ANY, mock.ANY)

    def test_get_pools(self):
        """Ensure get_pools exists and calls driver.get_pools."""
        mock_get_pools = self.mock_object(self.manager.driver, 'get_pools',
                                          mock.Mock(return_value='fake_pools'))

        result = self.manager.get_pools(self.context, filters='fake_filters')

        mock_get_pools.assert_called_once_with(self.context, 'fake_filters')
        self.assertEqual('fake_pools', result)


class SchedulerTestCase(test.TestCase):
    """Test case for base scheduler driver class."""

    # So we can subclass this test and re-use tests if we need.
    driver_cls = driver.Scheduler

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
            self.driver.host_manager.update_service_capabilities.\
                assert_called_once_with(service_name, host, capabilities)

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
                self.assertEqual(result, ['host2'])
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
            driver.share_update_db(self.context, 31337, 'fake_host')
            db.share_update.assert_called_once_with(
                self.context, 31337,
                {'host': 'fake_host', 'scheduled_at': 'fake-now'})


class SimpleSchedulerSharesTestCase(test.TestCase):
    """Test case for simple scheduler create share method."""

    def setUp(self):
        super(SimpleSchedulerSharesTestCase, self).setUp()
        self.mock_object(share_rpcapi, 'ShareAPI')
        self.driver = simple.SimpleScheduler()

        self.context = context.RequestContext('fake_user', 'fake_project')
        self.admin_context = context.RequestContext('fake_admin_user',
                                                    'fake_project')
        self.admin_context.is_admin = True

    @mock.patch.object(utils, 'service_is_up', mock.Mock(return_value=True))
    def test_create_share_if_two_services_up(self):
        share_id = 'fake'
        fake_share = {'id': share_id, 'size': 1}
        fake_service_1 = {'disabled': False, 'host': 'fake_host1'}
        fake_service_2 = {'disabled': False, 'host': 'fake_host2'}
        fake_result = [(fake_service_1, 2), (fake_service_2, 1)]
        fake_request_spec = {
            'share_id': share_id,
            'share_properties': fake_share,
        }
        self.mock_object(db, 'service_get_all_share_sorted',
                         mock.Mock(return_value=fake_result))
        self.mock_object(driver, 'share_update_db',
                         mock.Mock(return_value=db_utils.create_share()))

        self.driver.schedule_create_share(self.context,
                                          fake_request_spec, {})
        utils.service_is_up.assert_called_once_with(utils.IsAMatcher(dict))
        db.service_get_all_share_sorted.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        driver.share_update_db.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id, 'fake_host1')

    def test_create_share_if_services_not_available(self):
        share_id = 'fake'
        fake_share = {'id': share_id, 'size': 1}
        fake_result = []
        fake_request_spec = {
            'share_id': share_id,
            'share_properties': fake_share,
        }
        with mock.patch.object(db, 'service_get_all_share_sorted',
                               mock.Mock(return_value=fake_result)):
            self.assertRaises(exception.NoValidHost,
                              self.driver.schedule_create_share,
                              self.context, fake_request_spec, {})
            db.service_get_all_share_sorted.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))

    def test_create_share_if_max_gigabytes_exceeded(self):
        share_id = 'fake'
        fake_share = {'id': share_id, 'size': 10001}
        fake_service_1 = {'disabled': False, 'host': 'fake_host1'}
        fake_service_2 = {'disabled': False, 'host': 'fake_host2'}
        fake_result = [(fake_service_1, 5), (fake_service_2, 7)]
        fake_request_spec = {
            'share_id': share_id,
            'share_properties': fake_share,
        }
        with mock.patch.object(db, 'service_get_all_share_sorted',
                               mock.Mock(return_value=fake_result)):
            self.assertRaises(exception.NoValidHost,
                              self.driver.schedule_create_share,
                              self.context, fake_request_spec, {})
            db.service_get_all_share_sorted.assert_called_once_with(
                utils.IsAMatcher(context.RequestContext))

    @mock.patch.object(utils, 'service_is_up', mock.Mock(return_value=True))
    def test_create_share_availability_zone(self):
        share_id = 'fake'
        fake_share = {
            'id': share_id,
            'size': 1,
        }
        fake_instance = {
            'availability_zone_id': 'fake',
        }
        fake_service_1 = {
            'disabled': False, 'host': 'fake_host1',
            'availability_zone_id': 'fake',
        }
        fake_service_2 = {
            'disabled': False, 'host': 'fake_host2',
            'availability_zone_id': 'super_fake',
        }
        fake_result = [(fake_service_1, 0), (fake_service_2, 1)]
        fake_request_spec = {
            'share_id': share_id,
            'share_properties': fake_share,
            'share_instance_properties': fake_instance,
        }
        self.mock_object(db, 'service_get_all_share_sorted',
                         mock.Mock(return_value=fake_result))
        self.mock_object(driver, 'share_update_db',
                         mock.Mock(return_value=db_utils.create_share()))

        self.driver.schedule_create_share(self.context,
                                          fake_request_spec, {})
        utils.service_is_up.assert_called_once_with(fake_service_1)
        driver.share_update_db.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id,
            fake_service_1['host'])
        db.service_get_all_share_sorted.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))

    @mock.patch.object(utils, 'service_is_up', mock.Mock(return_value=True))
    def test_create_share_availability_zone_on_host(self):
        share_id = 'fake'
        fake_share = {
            'id': share_id,
            'availability_zone': 'fake:fake',
            'size': 1,
        }
        fake_service = {'disabled': False, 'host': 'fake'}
        fake_request_spec = {
            'share_id': share_id,
            'share_properties': fake_share,
        }
        self.mock_object(db, 'service_get_all_share_sorted',
                         mock.Mock(return_value=[(fake_service, 1)]))
        self.mock_object(driver, 'share_update_db',
                         mock.Mock(return_value=db_utils.create_share()))

        self.driver.schedule_create_share(self.admin_context,
                                          fake_request_spec, {})
        utils.service_is_up.assert_called_once_with(fake_service)
        db.service_get_all_share_sorted.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        driver.share_update_db.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id, 'fake')
