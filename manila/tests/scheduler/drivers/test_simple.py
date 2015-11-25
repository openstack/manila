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
Tests For Simple Scheduler
"""

import mock
from oslo_config import cfg

from manila import context
from manila import db
from manila import exception
from manila.scheduler.drivers import base
from manila.scheduler.drivers import simple
from manila.share import rpcapi as share_rpcapi
from manila import test
from manila.tests import db_utils
from manila import utils

CONF = cfg.CONF


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
        self.mock_object(base, 'share_update_db',
                         mock.Mock(return_value=db_utils.create_share()))

        self.driver.schedule_create_share(self.context,
                                          fake_request_spec, {})
        utils.service_is_up.assert_called_once_with(utils.IsAMatcher(dict))
        db.service_get_all_share_sorted.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        base.share_update_db.assert_called_once_with(
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
        self.mock_object(base, 'share_update_db',
                         mock.Mock(return_value=db_utils.create_share()))

        self.driver.schedule_create_share(self.context,
                                          fake_request_spec, {})
        utils.service_is_up.assert_called_once_with(fake_service_1)
        base.share_update_db.assert_called_once_with(
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
        self.mock_object(base, 'share_update_db',
                         mock.Mock(return_value=db_utils.create_share()))

        self.driver.schedule_create_share(self.admin_context,
                                          fake_request_spec, {})
        utils.service_is_up.assert_called_once_with(fake_service)
        db.service_get_all_share_sorted.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))
        base.share_update_db.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), share_id, 'fake')
