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

import mock

from manila import context
from manila import exception
from manila.share import manager
from manila import test
from manila import utils


class FakeAccessRule(object):

    def __init__(self, **kwargs):
        self.STATE_ACTIVE = 'active'
        self.STATE_NEW = 'new'
        self.STATE_ERROR = 'error'
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getitem__(self, item):
        return getattr(self, item)


class ShareManagerTestCase(test.TestCase):

    def setUp(self):
        super(ShareManagerTestCase, self).setUp()
        self.share_manager = manager.ShareManager()
        self.stubs.Set(self.share_manager.driver, 'do_setup', mock.Mock())
        self.stubs.Set(self.share_manager.driver, 'check_for_setup_error',
                       mock.Mock())

    def test_init_host_with_no_shares(self):
        self.stubs.Set(self.share_manager.db, 'share_get_all_by_host',
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
        self.stubs.Set(self.share_manager.db,
                       'share_get_all_by_host',
                       mock.Mock(return_value=shares))
        self.stubs.Set(self.share_manager.driver, 'ensure_share', mock.Mock())
        self.stubs.Set(self.share_manager, '_get_share_server',
                       mock.Mock(return_value=share_server))
        self.stubs.Set(self.share_manager, 'publish_service_capabilities',
                       mock.Mock())
        self.stubs.Set(self.share_manager.db, 'share_access_get_all_for_share',
                       mock.Mock(return_value=rules))
        self.stubs.Set(self.share_manager.driver, 'allow_access',
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
