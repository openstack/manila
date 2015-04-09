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
Unit tests for the NetApp Data ONTAP cDOT multi-SVM storage driver library.
"""

import copy

import ddt
import mock
from oslo_log import log

from manila import context
from manila import exception
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_base
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_multi_svm
from manila.share.drivers.netapp import utils as na_utils
from manila import test
from manila.tests.share.drivers.netapp.dataontap import fakes as fake


@ddt.ddt
class NetAppFileStorageLibraryTestCase(test.TestCase):

    def setUp(self):
        super(NetAppFileStorageLibraryTestCase, self).setUp()

        self.mock_object(na_utils, 'validate_driver_instantiation')

        # Mock loggers as themselves to allow logger arg validation
        mock_logger = log.getLogger('mock_logger')
        self.mock_object(lib_multi_svm.LOG,
                         'warning',
                         mock.Mock(side_effect=mock_logger.warning))
        self.mock_object(lib_multi_svm.LOG,
                         'error',
                         mock.Mock(side_effect=mock_logger.error))

        self.mock_db = mock.Mock()
        kwargs = {
            'configuration': fake.get_config_cmode(),
            'app_version': fake.APP_VERSION
        }

        self.library = lib_multi_svm.NetAppCmodeMultiSVMFileStorageLibrary(
            self.mock_db, fake.DRIVER_NAME, **kwargs)
        self.library._client = mock.Mock()
        self.library._client.get_ontapi_version.return_value = (1, 21)
        self.client = self.library._client
        self.context = mock.Mock()

    def test_check_for_setup_error_cluster_creds_no_vserver(self):
        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_check_data_ontap_version = self.mock_object(
            self.library, '_check_data_ontap_version')
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      'check_for_setup_error')

        self.library.check_for_setup_error()

        self.assertTrue(mock_check_data_ontap_version.called)
        self.assertTrue(self.library._find_matching_aggregates.called)
        mock_super.assert_called_once_with()

    def test_check_for_setup_error_cluster_creds_with_vserver(self):
        self.library._have_cluster_creds = True
        self.library.configuration.netapp_vserver = fake.VSERVER1
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      'check_for_setup_error')

        self.library.check_for_setup_error()

        mock_super.assert_called_once_with()
        self.assertTrue(self.library._find_matching_aggregates.called)
        self.assertTrue(lib_multi_svm.LOG.warning.called)

    def test_check_for_setup_error_vserver_creds(self):
        self.library._have_cluster_creds = False

        self.assertRaises(exception.InvalidInput,
                          self.library.check_for_setup_error)

    def test_check_for_setup_error_no_aggregates(self):
        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.NetAppException,
                          self.library.check_for_setup_error)
        self.assertTrue(self.library._find_matching_aggregates.called)

    @ddt.data((1, 20), (1, 21))
    def test_check_data_ontap_version(self, version):
        self.library._client.get_ontapi_version.return_value = version
        self.assertIsNone(self.library._check_data_ontap_version())

    @ddt.data((1, 30), (1, 31), (1, 40), (2, 0))
    def test_check_data_ontap_version_too_new(self, version):
        self.library._client.get_ontapi_version.return_value = version
        self.assertRaises(exception.NetAppException,
                          self.library._check_data_ontap_version)

    def test_get_vserver_no_share_server(self):

        self.assertRaises(exception.NetAppException,
                          self.library._get_vserver)

    def test_get_vserver_no_backend_details(self):

        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server.pop('backend_details')
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.NetAppException,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver_none_backend_details(self):

        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server['backend_details'] = None
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.NetAppException,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver_no_vserver(self):

        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server['backend_details'].pop('vserver_name')
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.NetAppException,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver_none_vserver(self):

        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server['backend_details']['vserver_name'] = None
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.NetAppException,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver_not_found(self):

        self.library._client.vserver_exists.return_value = False
        kwargs = {'share_server': fake.SHARE_SERVER}

        self.assertRaises(exception.VserverUnavailable,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver(self):

        self.library._client.vserver_exists.return_value = True
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value='fake_client'))

        result = self.library._get_vserver(share_server=fake.SHARE_SERVER)

        self.assertTupleEqual((fake.VSERVER1, 'fake_client'), result)

    def test_handle_housekeeping_tasks(self):

        self.mock_object(self.client, 'prune_deleted_nfs_export_policies')
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      '_handle_housekeeping_tasks')

        self.library._handle_housekeeping_tasks()

        self.assertTrue(self.client.prune_deleted_nfs_export_policies.called)
        self.assertTrue(mock_super.called)

    def test_find_matching_aggregates(self):

        self.mock_object(self.client,
                         'list_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))

        self.library.configuration.netapp_aggregate_name_search_pattern = (
            '.*_aggr_1')
        result = self.library._find_matching_aggregates()
        self.assertListEqual([fake.AGGREGATES[0]], result)

    def test_setup_server(self):

        mock_create_vserver = self.mock_object(
            self.library,
            '_create_vserver_if_nonexistent',
            mock.Mock(return_value=fake.VSERVER1))

        result = self.library.setup_server(fake.NETWORK_INFO)

        self.assertTrue(mock_create_vserver.called)
        self.assertDictEqual({'vserver_name': fake.VSERVER1}, result)

    def test_create_vserver_if_nonexistent(self):

        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id
        vserver_client = mock.Mock()

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        self.mock_object(self.library._client,
                         'vserver_exists',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library, '_create_vserver_lifs')

        result = self.library._create_vserver_if_nonexistent(
            fake.NETWORK_INFO)

        self.assertEqual(vserver_name, result)
        self.library.db.share_server_backend_details_set.assert_called_with(
            'fake_admin_context',
            vserver_id,
            {'vserver_name': vserver_name})
        self.library._get_api_client.assert_called_with(vserver=vserver_name)
        self.library._client.create_vserver.assert_called_with(
            vserver_name,
            fake.ROOT_VOLUME_AGGREGATE,
            fake.ROOT_VOLUME,
            fake.AGGREGATES)
        self.library._create_vserver_lifs.assert_called_with(
            vserver_name,
            vserver_client,
            fake.NETWORK_INFO)
        self.assertTrue(vserver_client.enable_nfs.called)
        self.library._client.setup_security_services.assert_called_with(
            fake.NETWORK_INFO['security_services'],
            vserver_client,
            vserver_name)

    def test_create_vserver_if_nonexistent_already_present(self):

        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        self.mock_object(self.library._client,
                         'vserver_exists',
                         mock.Mock(return_value=True))

        self.assertRaises(exception.NetAppException,
                          self.library._create_vserver_if_nonexistent,
                          fake.NETWORK_INFO)

        self.library.db.share_server_backend_details_set.assert_called_with(
            'fake_admin_context',
            vserver_id,
            {'vserver_name': vserver_name})

    @ddt.data(netapp_api.NaApiError, exception.NetAppException)
    def test_create_vserver_if_nonexistent_lif_creation_failure(self,
                                                                lif_exception):

        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id
        vserver_client = mock.Mock()

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        self.mock_object(self.library._client,
                         'vserver_exists',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library,
                         '_create_vserver_lifs',
                         mock.Mock(side_effect=lif_exception))

        self.assertRaises(lif_exception,
                          self.library._create_vserver_if_nonexistent,
                          fake.NETWORK_INFO)

        self.library.db.share_server_backend_details_set.assert_called_with(
            'fake_admin_context',
            vserver_id,
            {'vserver_name': vserver_name})
        self.library._get_api_client.assert_called_with(vserver=vserver_name)
        self.assertTrue(self.library._client.create_vserver.called)
        self.library._create_vserver_lifs.assert_called_with(
            vserver_name,
            vserver_client,
            fake.NETWORK_INFO)
        self.library._client.delete_vserver.assert_called_once_with(
            vserver_name,
            vserver_client)
        self.assertFalse(vserver_client.enable_nfs.called)
        self.assertEqual(1, lib_multi_svm.LOG.error.call_count)

    def test_create_vserver_lifs(self):

        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library,
                         '_get_node_data_port',
                         mock.Mock(return_value=fake.NODE_DATA_PORT))
        self.mock_object(self.library, '_create_lif_if_nonexistent')

        self.library._create_vserver_lifs(fake.VSERVER1,
                                          'fake_vserver_client',
                                          fake.NETWORK_INFO)

        self.library._create_lif_if_nonexistent.assert_has_calls([
            mock.call(
                fake.VSERVER1,
                fake.NETWORK_INFO['network_allocations'][0]['id'],
                fake.NETWORK_INFO['segmentation_id'],
                fake.CLUSTER_NODES[0],
                fake.NODE_DATA_PORT,
                fake.NETWORK_INFO['network_allocations'][0]['ip_address'],
                fake.NETWORK_INFO_NETMASK,
                'fake_vserver_client'),
            mock.call(
                fake.VSERVER1,
                fake.NETWORK_INFO['network_allocations'][1]['id'],
                fake.NETWORK_INFO['segmentation_id'],
                fake.CLUSTER_NODES[1],
                fake.NODE_DATA_PORT,
                fake.NETWORK_INFO['network_allocations'][1]['ip_address'],
                fake.NETWORK_INFO_NETMASK,
                'fake_vserver_client')])

    def test_get_node_data_port(self):

        self.mock_object(self.client,
                         'list_node_data_ports',
                         mock.Mock(return_value=fake.NODE_DATA_PORTS))
        self.library.configuration.netapp_port_name_search_pattern = 'e0c'

        result = self.library._get_node_data_port(fake.CLUSTER_NODE)

        self.assertEqual('e0c', result)
        self.library._client.list_node_data_ports.assert_has_calls([
            mock.call(fake.CLUSTER_NODE)])

    def test_get_node_data_port_no_match(self):

        self.mock_object(self.client,
                         'list_node_data_ports',
                         mock.Mock(return_value=fake.NODE_DATA_PORTS))
        self.library.configuration.netapp_port_name_search_pattern = 'ifgroup1'

        self.assertRaises(exception.NetAppException,
                          self.library._get_node_data_port,
                          fake.CLUSTER_NODE)

    def test_create_lif_if_nonexistent(self):

        vserver_client = mock.Mock()
        vserver_client.network_interface_exists = mock.Mock(
            return_value=False)

        self.library._create_lif_if_nonexistent('fake_vserver',
                                                'fake_allocation_id',
                                                'fake_vlan',
                                                'fake_node',
                                                'fake_port',
                                                'fake_ip',
                                                'fake_netmask',
                                                vserver_client)

        self.library._client.create_network_interface.assert_has_calls([
            mock.call(
                'fake_ip',
                'fake_netmask',
                'fake_vlan',
                'fake_node',
                'fake_port',
                'fake_vserver',
                'fake_allocation_id',
                fake.LIF_NAME_TEMPLATE)])

    def test_create_lif_if_nonexistent_already_present(self):

        vserver_client = mock.Mock()
        vserver_client.network_interface_exists = mock.Mock(
            return_value=True)

        self.library._create_lif_if_nonexistent('fake_vserver',
                                                'fake_allocation_id',
                                                'fake_vlan',
                                                'fake_node',
                                                'fake_port',
                                                'fake_ip',
                                                'fake_netmask',
                                                vserver_client)

        self.assertFalse(self.library._client.create_network_interface.called)

    def test_get_network_allocations_number(self):

        self.library._client.list_cluster_nodes.return_value = (
            fake.CLUSTER_NODES)

        result = self.library.get_network_allocations_number()

        self.assertEqual(len(fake.CLUSTER_NODES), result)

    def test_teardown_server(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))

        self.library.teardown_server(
            fake.SHARE_SERVER['backend_details'],
            security_services=fake.NETWORK_INFO['security_services'])

        self.library._client.delete_vserver.assert_called_once_with(
            fake.VSERVER1,
            vserver_client,
            security_services=fake.NETWORK_INFO['security_services'])
