# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
Unit tests for the NetApp Data ONTAP cDOT single-SVM storage driver library.
"""

import ddt
import mock
from oslo_log import log

from manila import exception
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_base
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_single_svm
from manila.share.drivers.netapp import utils as na_utils
from manila import test
import manila.tests.share.drivers.netapp.dataontap.fakes as fake


@ddt.ddt
class NetAppFileStorageLibraryTestCase(test.TestCase):

    def setUp(self):
        super(NetAppFileStorageLibraryTestCase, self).setUp()

        self.mock_object(na_utils, 'validate_driver_instantiation')

        # Mock loggers as themselves to allow logger arg validation
        mock_logger = log.getLogger('mock_logger')
        self.mock_object(lib_single_svm.LOG,
                         'info',
                         mock.Mock(side_effect=mock_logger.info))

        config = fake.get_config_cmode()
        config.netapp_vserver = fake.VSERVER1

        kwargs = {
            'configuration': config,
            'private_storage': mock.Mock(),
            'app_version': fake.APP_VERSION
        }

        self.library = lib_single_svm.NetAppCmodeSingleSVMFileStorageLibrary(
            fake.DRIVER_NAME, **kwargs)

        self.library._client = mock.Mock()
        self.client = self.library._client

    def test_init(self):
        self.assertEqual(fake.VSERVER1, self.library._vserver)

    def test_check_for_setup_error(self):

        self.library._client.vserver_exists.return_value = True
        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      'check_for_setup_error')

        self.library.check_for_setup_error()

        self.assertTrue(lib_single_svm.LOG.info.called)
        mock_super.assert_called_once_with()
        self.assertTrue(self.library._find_matching_aggregates.called)

    def test_check_for_setup_error_no_vserver(self):
        self.library._vserver = None

        self.assertRaises(exception.InvalidInput,
                          self.library.check_for_setup_error)

    def test_check_for_setup_error_vserver_not_found(self):
        self.library._client.vserver_exists.return_value = False

        self.assertRaises(exception.VserverNotFound,
                          self.library.check_for_setup_error)

    def test_check_for_setup_error_cluster_creds_vserver_match(self):
        self.library._client.vserver_exists.return_value = True
        self.library._have_cluster_creds = False
        self.library._client.list_vservers.return_value = [fake.VSERVER1]
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      'check_for_setup_error')

        self.library.check_for_setup_error()

        mock_super.assert_called_once_with()
        self.assertTrue(self.library._find_matching_aggregates.called)

    def test_check_for_setup_error_cluster_creds_vserver_mismatch(self):
        self.library._client.vserver_exists.return_value = True
        self.library._have_cluster_creds = False
        self.library._client.list_vservers.return_value = [fake.VSERVER2]

        self.assertRaises(exception.InvalidInput,
                          self.library.check_for_setup_error)

    def test_check_for_setup_error_no_aggregates(self):
        self.library._client.vserver_exists.return_value = True
        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.NetAppException,
                          self.library.check_for_setup_error)
        self.assertTrue(self.library._find_matching_aggregates.called)

    def test_get_vserver(self):
        self.library._client.vserver_exists.return_value = True
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value='fake_client'))

        result_vserver, result_vserver_client = self.library._get_vserver()

        self.assertEqual(fake.VSERVER1, result_vserver)
        self.assertEqual('fake_client', result_vserver_client)

    def test_get_vserver_share_server_specified(self):
        self.assertRaises(exception.InvalidParameterValue,
                          self.library._get_vserver,
                          share_server=fake.SHARE_SERVER)

    def test_get_vserver_no_vserver(self):
        self.library._vserver = None

        self.assertRaises(exception.InvalidInput,
                          self.library._get_vserver)

    def test_get_vserver_vserver_not_found(self):
        self.library._client.vserver_exists.return_value = False

        self.assertRaises(exception.VserverNotFound,
                          self.library._get_vserver)

    def test_get_ems_pool_info(self):

        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=['aggr1', 'aggr2']))

        result = self.library._get_ems_pool_info()

        expected = {
            'pools': {
                'vserver': fake.VSERVER1,
                'aggregates': ['aggr1', 'aggr2'],
            },
        }
        self.assertEqual(expected, result)

    @ddt.data(True, False)
    def test_handle_housekeeping_tasks_with_cluster_creds(self, have_creds):
        self.library._have_cluster_creds = have_creds
        mock_vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=mock_vserver_client))
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      '_handle_housekeeping_tasks')

        self.library._handle_housekeeping_tasks()

        self.assertTrue(
            mock_vserver_client.prune_deleted_nfs_export_policies.called)
        self.assertTrue(mock_vserver_client.prune_deleted_snapshots.called)
        self.assertIs(
            have_creds,
            mock_vserver_client.remove_unused_qos_policy_groups.called)
        self.assertTrue(mock_super.called)

    @ddt.data(True, False)
    def test_find_matching_aggregates(self, have_cluster_creds):

        self.library._have_cluster_creds = have_cluster_creds
        aggregates = fake.AGGREGATES + fake.ROOT_AGGREGATES
        mock_vserver_client = mock.Mock()
        mock_vserver_client.list_vserver_aggregates.return_value = aggregates
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=mock_vserver_client))
        mock_client = mock.Mock()
        mock_client.list_root_aggregates.return_value = fake.ROOT_AGGREGATES
        self.library._client = mock_client

        self.library.configuration.netapp_aggregate_name_search_pattern = (
            '.*_aggr_1')

        result = self.library._find_matching_aggregates()

        if have_cluster_creds:
            self.assertListEqual([fake.AGGREGATES[0]], result)
            mock_client.list_root_aggregates.assert_called_once_with()
        else:
            self.assertListEqual([fake.AGGREGATES[0], fake.ROOT_AGGREGATES[0]],
                                 result)
            self.assertFalse(mock_client.list_root_aggregates.called)

    def test_get_network_allocations_number(self):
        self.assertEqual(0, self.library.get_network_allocations_number())

    def test_get_admin_network_allocations_number(self):

        result = self.library.get_admin_network_allocations_number()

        self.assertEqual(0, result)
