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

from manila.common import constants
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

    def test_setup_server_2_net_allocations(self):
        # Setup required test data
        allocation_number = 2
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = {'id': 'fake_sn_id'}
        network_info = {'fake_network_info_key': 'fake_network_info_value'}
        server_info = {'fake_server_info_key': 'fake_server_info_value'}

        # mock required stuff
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(return_value=allocation_number))
        self.stubs.Set(self.share_manager.network_api, 'allocate_network',
                       mock.Mock())
        self.stubs.Set(self.share_manager, '_form_server_setup_info',
                       mock.Mock(return_value=network_info))
        self.stubs.Set(self.share_manager.driver, 'setup_server',
                       mock.Mock(return_value=server_info))
        self.stubs.Set(self.share_manager.db,
                       'share_server_backend_details_set',
                       mock.Mock())
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock(return_value=share_server))

        # execute method _setup_server
        result = self.share_manager._setup_server(
            context, share_server, metadata=metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_has_calls([
            mock.call(context, share_server['share_network_id']),
            mock.call(context, share_server['share_network_id']),
        ])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager.network_api.allocate_network.\
            assert_called_once_with(context, share_server, share_network,
                                    count=allocation_number)
        self.share_manager._form_server_setup_info.assert_called_once_with(
            context, share_server, share_network)
        self.share_manager.driver.setup_server.assert_called_once_with(
            network_info, metadata=metadata)
        self.share_manager.db.share_server_backend_details_set.\
            assert_called_once_with(context, share_server['id'], server_info)
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ACTIVE})

    def test_setup_server_no_net_allocations(self):
        # Setup required test data
        allocation_number = 0
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = {'id': 'fake_sn_id'}
        network_info = {'fake_network_info_key': 'fake_network_info_value'}
        server_info = {'fake_server_info_key': 'fake_server_info_value'}

        # mock required stuff
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(return_value=allocation_number))
        self.stubs.Set(self.share_manager, '_form_server_setup_info',
                       mock.Mock(return_value=network_info))
        self.stubs.Set(self.share_manager.driver, 'setup_server',
                       mock.Mock(return_value=server_info))
        self.stubs.Set(self.share_manager.db,
                       'share_server_backend_details_set',
                       mock.Mock())
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock(return_value=share_server))

        # execute method _setup_server
        result = self.share_manager._setup_server(
            context, share_server, metadata=metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_called_once_with(
            context, share_server['share_network_id'])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager._form_server_setup_info.assert_called_once_with(
            context, share_server, share_network)
        self.share_manager.driver.setup_server.assert_called_once_with(
            network_info, metadata=metadata)
        self.share_manager.db.share_server_backend_details_set.\
            assert_called_once_with(context, share_server['id'], server_info)
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ACTIVE})

    def test_setup_server_server_info_not_present_no_net_allocations(self):
        # Setup required test data
        allocation_number = 0
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        metadata = {'fake_metadata_key': 'fake_metadata_value'}
        share_network = {'id': 'fake_sn_id'}
        network_info = {'fake_network_info_key': 'fake_network_info_value'}
        server_info = {}

        # mock required stuff
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(return_value=allocation_number))
        self.stubs.Set(self.share_manager, '_form_server_setup_info',
                       mock.Mock(return_value=network_info))
        self.stubs.Set(self.share_manager.driver, 'setup_server',
                       mock.Mock(return_value=server_info))
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock(return_value=share_server))

        # execute method _setup_server
        result = self.share_manager._setup_server(
            context, share_server, metadata=metadata)

        # verify results
        self.assertEqual(share_server, result)
        self.share_manager.db.share_network_get.assert_called_once_with(
            context, share_server['share_network_id'])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager._form_server_setup_info.assert_called_once_with(
            context, share_server, share_network)
        self.share_manager.driver.setup_server.assert_called_once_with(
            network_info, metadata=metadata)
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ACTIVE})

    def test_setup_server_exception_raised(self):
        # Setup required test data
        context = "fake_context"
        share_server = {
            'id': 'fake_id',
            'share_network_id': 'fake_sn_id',
        }
        share_network = {'id': 'fake_sn_id'}

        # mock required stuff
        self.stubs.Set(self.share_manager.db, 'share_network_get',
                       mock.Mock(return_value=share_network))
        self.stubs.Set(self.share_manager.driver,
                       'get_network_allocations_number',
                       mock.Mock(side_effect=exception.ManilaException()))
        self.stubs.Set(self.share_manager.db, 'share_server_update',
                       mock.Mock())
        self.stubs.Set(self.share_manager.network_api, 'deallocate_network',
                       mock.Mock())

        # execute method _setup_server
        self.assertRaises(
            exception.ManilaException,
            self.share_manager._setup_server,
            context,
            share_server,
        )
        self.share_manager.db.share_network_get.assert_called_once_with(
            context, share_server['share_network_id'])
        self.share_manager.driver.get_network_allocations_number.\
            assert_called_once_with()
        self.share_manager.db.share_server_update.assert_called_once_with(
            context, share_server['id'], {'status': constants.STATUS_ERROR})
        self.share_manager.network_api.deallocate_network.\
            assert_called_once_with(context, share_network)
