# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from mox import IsA

from manila import context
from manila import db
from manila import exception
from manila import flags
from manila.openstack.common import timeutils
from manila.scheduler import driver
from manila.scheduler import manager
from manila.scheduler import simple
from manila import test
from manila import utils


FLAGS = flags.FLAGS


class SchedulerManagerTestCase(test.TestCase):
    """Test case for scheduler manager."""

    manager_cls = manager.SchedulerManager
    driver_cls = driver.Scheduler
    driver_cls_name = 'manila.scheduler.driver.Scheduler'

    class AnException(Exception):
        pass

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

        self.mox.StubOutWithMock(self.manager.driver,
                                 'update_service_capabilities')

        # Test no capabilities passes empty dictionary
        self.manager.driver.update_service_capabilities(service_name,
                                                        host, {})
        self.mox.ReplayAll()
        result = self.manager.update_service_capabilities(
            self.context,
            service_name=service_name,
            host=host)
        self.mox.VerifyAll()

        self.mox.ResetAll()
        # Test capabilities passes correctly
        capabilities = {'fake_capability': 'fake_value'}
        self.manager.driver.update_service_capabilities(service_name,
                                                        host,
                                                        capabilities)
        self.mox.ReplayAll()
        result = self.manager.update_service_capabilities(
            self.context,
            service_name=service_name, host=host,
            capabilities=capabilities)

    def test_create_volume_exception_puts_volume_in_error_state(self):
        """Test that a NoValideHost exception for create_volume.

        Puts the volume in 'error' state and eats the exception.
        """
        fake_volume_id = 1
        self._mox_schedule_method_helper('schedule_create_volume')
        self.mox.StubOutWithMock(db, 'volume_update')

        topic = 'fake_topic'
        volume_id = fake_volume_id
        request_spec = {'volume_id': fake_volume_id}

        self.manager.driver.schedule_create_volume(
            self.context,
            request_spec, {}).AndRaise(exception.NoValidHost(reason=""))
        db.volume_update(self.context, fake_volume_id, {'status': 'error'})

        self.mox.ReplayAll()
        self.manager.create_volume(self.context, topic, volume_id,
                                   request_spec=request_spec,
                                   filter_properties={})

    def test_create_share_exception_puts_share_in_error_state(self):
        """Test that a NoValideHost exception for create_share.

        Puts the share in 'error' state and eats the exception.
        """
        fake_share_id = 1
        self._mox_schedule_method_helper('schedule_create_share')
        self.mox.StubOutWithMock(db, 'share_update')

        topic = 'fake_topic'
        share_id = fake_share_id
        request_spec = {'share_id': fake_share_id}

        self.manager.driver.schedule_create_share(
            self.context,
            request_spec, {}).AndRaise(exception.NoValidHost(reason=""))
        db.share_update(self.context, fake_share_id, {'status': 'error'})

        self.mox.ReplayAll()
        self.manager.create_share(self.context, topic, share_id,
                                  request_spec=request_spec,
                                  filter_properties={})

    def _mox_schedule_method_helper(self, method_name):
        # Make sure the method exists that we're going to test call
        def stub_method(*args, **kwargs):
            pass

        setattr(self.manager.driver, method_name, stub_method)

        self.mox.StubOutWithMock(self.manager.driver,
                                 method_name)


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

        self.mox.StubOutWithMock(self.driver.host_manager,
                                 'update_service_capabilities')

        capabilities = {'fake_capability': 'fake_value'}
        self.driver.host_manager.update_service_capabilities(service_name,
                                                             host,
                                                             capabilities)
        self.mox.ReplayAll()
        result = self.driver.update_service_capabilities(service_name,
                                                         host,
                                                         capabilities)

    def test_hosts_up(self):
        service1 = {'host': 'host1'}
        service2 = {'host': 'host2'}
        services = [service1, service2]

        self.mox.StubOutWithMock(db, 'service_get_all_by_topic')
        self.mox.StubOutWithMock(utils, 'service_is_up')

        db.service_get_all_by_topic(self.context,
                                    self.topic).AndReturn(services)
        utils.service_is_up(service1).AndReturn(False)
        utils.service_is_up(service2).AndReturn(True)

        self.mox.ReplayAll()
        result = self.driver.hosts_up(self.context, self.topic)
        self.assertEqual(result, ['host2'])


class SchedulerDriverBaseTestCase(SchedulerTestCase):
    """Test cases for base scheduler driver class methods
       that can't will fail if the driver is changed"""

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

    def test_volume_host_update_db(self):
        self.mox.StubOutWithMock(timeutils, 'utcnow')
        self.mox.StubOutWithMock(db, 'volume_update')

        timeutils.utcnow().AndReturn('fake-now')
        db.volume_update(self.context, 31337,
                         {'host': 'fake_host',
                          'scheduled_at': 'fake-now'})

        self.mox.ReplayAll()
        driver.volume_update_db(self.context, 31337, 'fake_host')

    def test_share_host_update_db(self):
        self.mox.StubOutWithMock(timeutils, 'utcnow')
        self.mox.StubOutWithMock(db, 'share_update')

        timeutils.utcnow().AndReturn('fake-now')
        db.share_update(self.context, 31337,
                        {'host': 'fake_host',
                         'scheduled_at': 'fake-now'})

        self.mox.ReplayAll()
        driver.share_update_db(self.context, 31337, 'fake_host')


class SimpleSchedulerSharesTestCase(test.TestCase):
    """Test case for simple scheduler create share method."""
    driver = simple.SimpleScheduler()

    def setUp(self):
        super(SimpleSchedulerSharesTestCase, self).setUp()
        self.context = context.RequestContext('fake_user', 'fake_project')
        self.admin_context = context.RequestContext('fake_admin_user',
                                                    'fake_project')
        self.admin_context.is_admin = True

    def test_create_share_if_two_services_up(self):
        share_id = 'fake'
        fake_share = {'id': share_id, 'size': 1}

        fake_service_1 = {'disabled': False, 'host': 'fake_host1'}

        fake_service_2 = {'disabled': False, 'host': 'fake_host2'}

        fake_result = [(fake_service_1, 2), (fake_service_2, 1)]

        self.mox.StubOutWithMock(db, 'service_get_all_share_sorted')
        self.mox.StubOutWithMock(utils, 'service_is_up')
        self.mox.StubOutWithMock(driver, 'share_update_db')

        fake_request_spec = {'share_id': share_id,
                             'share_properties': fake_share}

        db.service_get_all_share_sorted(IsA(context.RequestContext))\
            .AndReturn(fake_result)
        utils.service_is_up(IsA(dict)).AndReturn(True)
        driver.share_update_db(IsA(context.RequestContext), share_id,
                               'fake_host1').AndReturn(fake_share)
        self.mox.ReplayAll()

        self.driver.schedule_create_share(self.context, fake_request_spec, {})

    def test_create_share_if_services_not_available(self):
        share_id = 'fake'
        fake_share = {'id': share_id, 'size': 1}

        fake_result = []

        fake_request_spec = {'share_id': share_id,
                             'share_properties': fake_share}

        self.mox.StubOutWithMock(db, 'service_get_all_share_sorted')

        db.service_get_all_share_sorted(IsA(context.RequestContext))\
            .AndReturn(fake_result)

        self.mox.ReplayAll()

        self.assertRaises(exception.NoValidHost,
                          self.driver.schedule_create_share,
                          self.context, fake_request_spec, {})

    def test_create_share_if_max_gigabytes_exceeded(self):
        share_id = 'fake'
        fake_share = {'id': share_id, 'size': 10001}

        fake_service_1 = {'disabled': False, 'host': 'fake_host1'}

        fake_service_2 = {'disabled': False, 'host': 'fake_host2'}

        fake_result = [(fake_service_1, 5), (fake_service_2, 7)]

        fake_request_spec = {'share_id': share_id,
                             'share_properties': fake_share}

        self.mox.StubOutWithMock(db, 'service_get_all_share_sorted')

        db.service_get_all_share_sorted(IsA(context.RequestContext))\
            .AndReturn(fake_result)

        self.mox.ReplayAll()

        self.assertRaises(exception.NoValidHost,
                          self.driver.schedule_create_share,
                          self.context, fake_request_spec, {})

    def test_create_share_availability_zone(self):
        share_id = 'fake'
        fake_share = {'id': share_id,
                      'availability_zone': 'fake:fake',
                      'size': 1}

        fake_service_1 = {'disabled': False, 'host': 'fake_host1',
                          'availability_zone': 'fake'}

        fake_service_2 = {'disabled': False, 'host': 'fake_host2',
                          'availability_zone': 'super_fake'}

        fake_result = [(fake_service_1, 0), (fake_service_2, 1)]

        fake_request_spec = {'share_id': share_id,
                             'share_properties': fake_share}

        self.mox.StubOutWithMock(utils, 'service_is_up')
        self.mox.StubOutWithMock(driver, 'share_update_db')
        self.mox.StubOutWithMock(db, 'service_get_all_share_sorted')

        db.service_get_all_share_sorted(IsA(context.RequestContext))\
            .AndReturn(fake_result)

        utils.service_is_up(fake_service_1).AndReturn(True)
        driver.share_update_db(IsA(context.RequestContext), share_id,
                               fake_service_1['host']).AndReturn(fake_share)

        self.mox.ReplayAll()
        self.driver.schedule_create_share(self.context, fake_request_spec, {})

    def test_create_share_availability_zone_on_host(self):
        share_id = 'fake'
        fake_share = {'id': share_id,
                      'availability_zone': 'fake:fake',
                      'size': 1}

        fake_request_spec = {'share_id': share_id,
                             'share_properties': fake_share}

        self.mox.StubOutWithMock(utils, 'service_is_up')
        self.mox.StubOutWithMock(db, 'service_get_by_args')
        self.mox.StubOutWithMock(driver, 'share_update_db')

        db.service_get_by_args(IsA(context.RequestContext), 'fake',
                               'manila-share').AndReturn('fake_service')
        utils.service_is_up('fake_service').AndReturn(True)
        driver.share_update_db(IsA(context.RequestContext), share_id,
                               'fake').AndReturn(fake_share)

        self.mox.ReplayAll()
        self.driver.schedule_create_share(self.admin_context,
                                          fake_request_spec, {})

    def test_create_share_availability_zone_if_service_down(self):
        share_id = 'fake'
        fake_share = {'id': share_id,
                      'availability_zone': 'fake:fake',
                      'size': 1}

        fake_request_spec = {'share_id': share_id,
                             'share_properties': fake_share}

        self.mox.StubOutWithMock(utils, 'service_is_up')
        self.mox.StubOutWithMock(db, 'service_get_by_args')

        db.service_get_by_args(IsA(context.RequestContext), 'fake',
                               'manila-share').AndReturn('fake_service')
        utils.service_is_up('fake_service').AndReturn(False)

        self.mox.ReplayAll()
        self.assertRaises(exception.WillNotSchedule,
                          self.driver.schedule_create_share,
                          self.admin_context, fake_request_spec, {})
