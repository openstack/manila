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
from unittest import mock

import ddt
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import units

from manila.common import constants
from manila import context
from manila import exception
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.cluster_mode import data_motion
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_base
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_multi_svm
from manila.share.drivers.netapp import utils as na_utils
from manila.share import share_types
from manila.share import utils as share_utils
from manila import test
from manila.tests.share.drivers.netapp.dataontap.client import fakes as c_fake
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

        kwargs = {
            'configuration': fake.get_config_cmode(),
            'private_storage': mock.Mock(),
            'app_version': fake.APP_VERSION
        }

        self.library = lib_multi_svm.NetAppCmodeMultiSVMFileStorageLibrary(
            fake.DRIVER_NAME, **kwargs)
        self.library._client = mock.Mock()
        self.library._client.get_ontapi_version.return_value = (1, 21)
        self.client = self.library._client
        self.fake_new_replica = copy.deepcopy(fake.SHARE)
        self.fake_new_ss = copy.deepcopy(fake.SHARE_SERVER)
        self.fake_new_vserver_name = 'fake_new_vserver'
        self.fake_new_ss['backend_details']['vserver_name'] = (
            self.fake_new_vserver_name
        )
        self.fake_new_replica['share_server'] = self.fake_new_ss
        self.fake_new_replica_host = 'fake_new_host'
        self.fake_replica = copy.deepcopy(fake.SHARE)
        self.fake_replica['id'] = fake.SHARE_ID2
        fake_ss = copy.deepcopy(fake.SHARE_SERVER)
        self.fake_vserver = 'fake_vserver'
        fake_ss['backend_details']['vserver_name'] = (
            self.fake_vserver
        )
        self.fake_replica['share_server'] = fake_ss
        self.fake_replica_host = 'fake_host'

        self.fake_new_client = mock.Mock()
        self.fake_client = mock.Mock()
        self.library._default_nfs_config = fake.NFS_CONFIG_DEFAULT

        # Server migration
        self.dm_session = data_motion.DataMotionSession()
        self.fake_src_share = copy.deepcopy(fake.SHARE)
        self.fake_src_share_server = copy.deepcopy(fake.SHARE_SERVER)
        self.fake_src_vserver = 'source_vserver'
        self.fake_src_backend_name = (
            self.fake_src_share_server['host'].split('@')[1])
        self.fake_src_share_server['backend_details']['vserver_name'] = (
            self.fake_src_vserver
        )
        self.fake_src_share['share_server'] = self.fake_src_share_server
        self.fake_src_share['id'] = 'fb9be037-8a75-4c2a-bb7d-f63dffe13015'
        self.fake_src_vol_name = 'share_fb9be037_8a75_4c2a_bb7d_f63dffe13015'
        self.fake_dest_share = copy.deepcopy(fake.SHARE)
        self.fake_dest_share_server = copy.deepcopy(fake.SHARE_SERVER_2)
        self.fake_dest_vserver = 'dest_vserver'
        self.fake_dest_backend_name = (
            self.fake_dest_share_server['host'].split('@')[1])
        self.fake_dest_share_server['backend_details']['vserver_name'] = (
            self.fake_dest_vserver
        )
        self.fake_dest_share['share_server'] = self.fake_dest_share_server
        self.fake_dest_share['id'] = 'aa6a3941-f87f-4874-92ca-425d3df85457'
        self.fake_dest_vol_name = 'share_aa6a3941_f87f_4874_92ca_425d3df85457'

        self.mock_src_client = mock.Mock()
        self.mock_dest_client = mock.Mock()

    def test_check_for_setup_error_cluster_creds_no_vserver(self):
        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      'check_for_setup_error')

        self.library.check_for_setup_error()

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

    def test_get_vserver_no_share_server(self):

        self.assertRaises(exception.InvalidInput,
                          self.library._get_vserver)

    def test_get_vserver_no_share_server_with_vserver_name(self):
        fake_vserver_client = mock.Mock()

        mock_vserver_exists = self.mock_object(
            fake_vserver_client, 'vserver_exists',
            mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=fake_vserver_client))

        result_vserver, result_vserver_client = self.library._get_vserver(
            share_server=None, vserver_name=fake.VSERVER1)

        mock_vserver_exists.assert_called_once_with(
            fake.VSERVER1
        )
        self.assertEqual(fake.VSERVER1, result_vserver)
        self.assertEqual(fake_vserver_client, result_vserver_client)

    def test_get_vserver_no_backend_details(self):

        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server.pop('backend_details')
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.VserverNotSpecified,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver_none_backend_details(self):

        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server['backend_details'] = None
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.VserverNotSpecified,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver_no_vserver(self):

        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server['backend_details'].pop('vserver_name')
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.VserverNotSpecified,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver_none_vserver(self):

        fake_share_server = copy.deepcopy(fake.SHARE_SERVER)
        fake_share_server['backend_details']['vserver_name'] = None
        kwargs = {'share_server': fake_share_server}

        self.assertRaises(exception.VserverNotSpecified,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver_not_found(self):

        mock_client = mock.Mock()
        mock_client.vserver_exists.return_value = False
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=mock_client))
        kwargs = {'share_server': fake.SHARE_SERVER}

        self.assertRaises(exception.VserverNotFound,
                          self.library._get_vserver,
                          **kwargs)

    def test_get_vserver(self):

        mock_client = mock.Mock()
        mock_client.vserver_exists.return_value = True
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=mock_client))

        result = self.library._get_vserver(share_server=fake.SHARE_SERVER)

        self.assertTupleEqual((fake.VSERVER1, mock_client), result)

    def test_get_ems_pool_info(self):

        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=['aggr1', 'aggr2']))

        result = self.library._get_ems_pool_info()

        expected = {
            'pools': {
                'vserver': None,
                'aggregates': ['aggr1', 'aggr2'],
            },
        }
        self.assertEqual(expected, result)

    @ddt.data({'fake_vserver_name': fake, 'nfs_config_support': False},
              {'fake_vserver_name': fake.IDENTIFIER,
               'nfs_config_support': True})
    @ddt.unpack
    def test_manage_server(self, fake_vserver_name, nfs_config_support):

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        mock_get_vserver_name = self.mock_object(
            self.library, '_get_vserver_name',
            mock.Mock(return_value=fake_vserver_name))
        self.library.is_nfs_config_supported = nfs_config_support
        mock_get_nfs_config = self.mock_object(
            self.library._client, 'get_nfs_config',
            mock.Mock(return_value=fake.NFS_CONFIG_DEFAULT))

        new_identifier, new_details = self.library.manage_server(
            context, fake.SHARE_SERVER, fake.IDENTIFIER, {})

        mock_get_vserver_name.assert_called_once_with(fake.SHARE_SERVER['id'])
        self.assertEqual(fake_vserver_name, new_details['vserver_name'])
        self.assertEqual(fake_vserver_name, new_identifier)
        if nfs_config_support:
            mock_get_nfs_config.assert_called_once_with(
                list(self.library.NFS_CONFIG_EXTRA_SPECS_MAP.values()),
                fake_vserver_name)
            self.assertEqual(jsonutils.dumps(fake.NFS_CONFIG_DEFAULT),
                             new_details['nfs_config'])
        else:
            mock_get_nfs_config.assert_not_called()

    def test_get_share_server_network_info(self):

        fake_vserver_client = mock.Mock()

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=['fake', fake_vserver_client]))

        net_interfaces = copy.deepcopy(c_fake.NETWORK_INTERFACES_MULTIPLE)

        self.mock_object(fake_vserver_client,
                         'get_network_interfaces',
                         mock.Mock(return_value=net_interfaces))

        result = self.library.get_share_server_network_info(context,
                                                            fake.SHARE_SERVER,
                                                            fake.IDENTIFIER,
                                                            {})
        mock_get_vserver.assert_called_once_with(
            vserver_name=fake.IDENTIFIER
        )
        reference_allocations = []
        for lif in net_interfaces:
            reference_allocations.append(lif['address'])

        self.assertEqual(reference_allocations, result)

    @ddt.data((True, fake.IDENTIFIER),
              (False, fake.IDENTIFIER))
    @ddt.unpack
    def test__verify_share_server_name(self, vserver_exists, identifier):

        mock_exists = self.mock_object(self.client, 'vserver_exists',
                                       mock.Mock(return_value=vserver_exists))
        expected_result = identifier
        if not vserver_exists:
            expected_result = self.library._get_vserver_name(identifier)

        result = self.library._get_correct_vserver_old_name(identifier)

        self.assertEqual(result, expected_result)
        mock_exists.assert_called_once_with(identifier)

    def test_handle_housekeeping_tasks(self):

        self.mock_object(self.client, 'prune_deleted_nfs_export_policies')
        self.mock_object(self.client, 'prune_deleted_snapshots')
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      '_handle_housekeeping_tasks')

        self.library._handle_housekeeping_tasks()

        self.assertTrue(self.client.prune_deleted_nfs_export_policies.called)
        self.assertTrue(self.client.prune_deleted_snapshots.called)
        self.assertTrue(mock_super.called)

    def test_find_matching_aggregates(self):

        mock_list_non_root_aggregates = self.mock_object(
            self.client, 'list_non_root_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        self.library.configuration.netapp_aggregate_name_search_pattern = (
            '.*_aggr_1')

        result = self.library._find_matching_aggregates()

        self.assertListEqual([fake.AGGREGATES[0]], result)
        mock_list_non_root_aggregates.assert_called_once_with()

    @ddt.data({'nfs_config_support': False},
              {'nfs_config_support': True,
               'nfs_config': fake.NFS_CONFIG_UDP_MAX},
              {'nfs_config_support': True,
               'nfs_config': fake.NFS_CONFIG_DEFAULT})
    @ddt.unpack
    def test_setup_server(self, nfs_config_support, nfs_config=None):
        mock_get_vserver_name = self.mock_object(
            self.library,
            '_get_vserver_name',
            mock.Mock(return_value=fake.VSERVER1))

        mock_create_vserver = self.mock_object(self.library, '_create_vserver')
        mock_validate_network_type = self.mock_object(
            self.library,
            '_validate_network_type')
        self.library.is_nfs_config_supported = nfs_config_support
        mock_get_extra_spec = self.mock_object(
            share_types, "get_share_type_extra_specs",
            mock.Mock(return_value=fake.EXTRA_SPEC))
        mock_check_extra_spec = self.mock_object(
            self.library,
            '_check_nfs_config_extra_specs_validity',
            mock.Mock())
        mock_get_nfs_config = self.mock_object(
            self.library,
            "_get_nfs_config_provisioning_options",
            mock.Mock(return_value=nfs_config))

        result = self.library.setup_server(fake.NETWORK_INFO,
                                           fake.SERVER_METADATA)

        ports = {}
        for network_allocation in fake.NETWORK_INFO['network_allocations']:
            ports[network_allocation['id']] = network_allocation['ip_address']

        self.assertTrue(mock_validate_network_type.called)
        self.assertTrue(mock_get_vserver_name.called)
        self.assertTrue(mock_create_vserver.called)
        if nfs_config_support:
            mock_get_extra_spec.assert_called_once_with(
                fake.SERVER_METADATA['share_type_id'])
            mock_check_extra_spec.assert_called_once_with(
                fake.EXTRA_SPEC)
            mock_get_nfs_config.assert_called_once_with(
                fake.EXTRA_SPEC)
        else:
            mock_get_extra_spec.assert_not_called()
            mock_check_extra_spec.assert_not_called()
            mock_get_nfs_config.assert_not_called()

        expected = {
            'vserver_name': fake.VSERVER1,
            'ports': jsonutils.dumps(ports),
        }
        if nfs_config_support:
            expected.update({'nfs_config': jsonutils.dumps(nfs_config)})
        self.assertDictEqual(expected, result)

    def test_setup_server_with_error(self):
        self.library.is_nfs_config_supported = False
        mock_get_vserver_name = self.mock_object(
            self.library,
            '_get_vserver_name',
            mock.Mock(return_value=fake.VSERVER1))

        fake_exception = exception.ManilaException("fake")
        mock_create_vserver = self.mock_object(
            self.library,
            '_create_vserver',
            mock.Mock(side_effect=fake_exception))

        mock_validate_network_type = self.mock_object(
            self.library,
            '_validate_network_type')

        self.assertRaises(
            exception.ManilaException,
            self.library.setup_server,
            fake.NETWORK_INFO,
            fake.SERVER_METADATA)

        ports = {}
        for network_allocation in fake.NETWORK_INFO['network_allocations']:
            ports[network_allocation['id']] = network_allocation['ip_address']

        self.assertTrue(mock_validate_network_type.called)
        self.assertTrue(mock_get_vserver_name.called)
        self.assertTrue(mock_create_vserver.called)

        self.assertDictEqual(
            {'server_details': {
                'vserver_name': fake.VSERVER1,
                'ports': jsonutils.dumps(ports),
            }},
            fake_exception.detail_data)

    @ddt.data(
        {'network_info': {'network_type': 'vlan', 'segmentation_id': 1000}},
        {'network_info': {'network_type': None, 'segmentation_id': None}},
        {'network_info': {'network_type': 'flat', 'segmentation_id': None}})
    @ddt.unpack
    def test_validate_network_type_with_valid_network_types(self,
                                                            network_info):
        self.library._validate_network_type(network_info)

    @ddt.data(
        {'network_info': {'network_type': 'vxlan', 'segmentation_id': 1000}},
        {'network_info': {'network_type': 'gre', 'segmentation_id': 100}})
    @ddt.unpack
    def test_validate_network_type_with_invalid_network_types(self,
                                                              network_info):
        self.assertRaises(exception.NetworkBadConfigurationException,
                          self.library._validate_network_type,
                          network_info)

    def test_get_vserver_name(self):
        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id

        actual_result = self.library._get_vserver_name(vserver_id)

        self.assertEqual(vserver_name, actual_result)

    @ddt.data({'existing_ipspace': None,
               'nfs_config': fake.NFS_CONFIG_TCP_UDP_MAX},
              {'existing_ipspace': fake.IPSPACE, 'nfs_config': None})
    @ddt.unpack
    def test_create_vserver(self, existing_ipspace, nfs_config):

        versions = ['fake_v1', 'fake_v2']
        self.library.configuration.netapp_enabled_share_protocols = versions
        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id
        vserver_client = mock.Mock()

        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library,
                         '_get_node_data_port',
                         mock.Mock(return_value='fake_port'))
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
                         '_create_ipspace',
                         mock.Mock(return_value=fake.IPSPACE))
        get_ipspace_name_for_vlan_port = self.mock_object(
            self.library._client,
            'get_ipspace_name_for_vlan_port',
            mock.Mock(return_value=existing_ipspace))
        self.mock_object(self.library, '_create_vserver_lifs')
        self.mock_object(self.library, '_create_vserver_admin_lif')
        self.mock_object(self.library, '_create_vserver_routes')

        self.library._create_vserver(vserver_name, fake.NETWORK_INFO,
                                     fake.NFS_CONFIG_TCP_UDP_MAX,
                                     nfs_config=nfs_config)

        get_ipspace_name_for_vlan_port.assert_called_once_with(
            fake.CLUSTER_NODES[0],
            'fake_port',
            fake.NETWORK_INFO['segmentation_id'])
        if not existing_ipspace:
            self.library._create_ipspace.assert_called_once_with(
                fake.NETWORK_INFO)
        self.library._client.create_vserver.assert_called_once_with(
            vserver_name, fake.ROOT_VOLUME_AGGREGATE, fake.ROOT_VOLUME,
            fake.AGGREGATES, fake.IPSPACE)
        self.library._get_api_client.assert_called_once_with(
            vserver=vserver_name)
        self.library._create_vserver_lifs.assert_called_once_with(
            vserver_name, vserver_client, fake.NETWORK_INFO, fake.IPSPACE)
        self.library._create_vserver_admin_lif.assert_called_once_with(
            vserver_name, vserver_client, fake.NETWORK_INFO, fake.IPSPACE)
        self.library._create_vserver_routes.assert_called_once_with(
            vserver_client, fake.NETWORK_INFO)
        vserver_client.enable_nfs.assert_called_once_with(
            versions, nfs_config=nfs_config)
        self.library._client.setup_security_services.assert_called_once_with(
            fake.NETWORK_INFO['security_services'], vserver_client,
            vserver_name)

    @ddt.data(None, fake.IPSPACE)
    def test_create_vserver_dp_destination(self, existing_ipspace):
        versions = ['fake_v1', 'fake_v2']
        self.library.configuration.netapp_enabled_share_protocols = versions
        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id

        self.mock_object(self.library._client,
                         'vserver_exists',
                         mock.Mock(return_value=False))
        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library,
                         '_get_node_data_port',
                         mock.Mock(return_value='fake_port'))
        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library,
                         '_create_ipspace',
                         mock.Mock(return_value=fake.IPSPACE))

        get_ipspace_name_for_vlan_port = self.mock_object(
            self.library._client,
            'get_ipspace_name_for_vlan_port',
            mock.Mock(return_value=existing_ipspace))
        self.mock_object(self.library, '_create_port_and_broadcast_domain')

        self.library._create_vserver(vserver_name, fake.NETWORK_INFO,
                                     metadata={'migration_destination': True})

        get_ipspace_name_for_vlan_port.assert_called_once_with(
            fake.CLUSTER_NODES[0],
            'fake_port',
            fake.NETWORK_INFO['segmentation_id'])
        if not existing_ipspace:
            self.library._create_ipspace.assert_called_once_with(
                fake.NETWORK_INFO)
        create_server_mock = self.library._client.create_vserver_dp_destination
        create_server_mock.assert_called_once_with(
            vserver_name, fake.AGGREGATES, fake.IPSPACE)
        self.library._create_port_and_broadcast_domain.assert_called_once_with(
            fake.IPSPACE, fake.NETWORK_INFO)

    def test_create_vserver_already_present(self):

        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id

        self.mock_object(context,
                         'get_admin_context',
                         mock.Mock(return_value='fake_admin_context'))
        self.mock_object(self.library._client,
                         'vserver_exists',
                         mock.Mock(return_value=True))

        self.assertRaises(exception.NetAppException,
                          self.library._create_vserver,
                          vserver_name,
                          fake.NETWORK_INFO,
                          fake.NFS_CONFIG_TCP_UDP_MAX)

    @ddt.data(
        {'network_exception': netapp_api.NaApiError,
         'existing_ipspace': fake.IPSPACE},
        {'network_exception': netapp_api.NaApiError,
         'existing_ipspace': None},
        {'network_exception': exception.NetAppException,
         'existing_ipspace': None},
        {'network_exception': exception.NetAppException,
         'existing_ipspace': fake.IPSPACE})
    @ddt.unpack
    def test_create_vserver_lif_creation_failure(self,
                                                 network_exception,
                                                 existing_ipspace):

        vserver_id = fake.NETWORK_INFO['server_id']
        vserver_name = fake.VSERVER_NAME_TEMPLATE % vserver_id
        vserver_client = mock.Mock()
        security_service = fake.NETWORK_INFO['security_services']

        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library,
                         '_get_node_data_port',
                         mock.Mock(return_value='fake_port'))
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
        self.mock_object(self.library._client,
                         'get_ipspace_name_for_vlan_port',
                         mock.Mock(return_value=existing_ipspace))
        self.mock_object(self.library,
                         '_create_ipspace',
                         mock.Mock(return_value=fake.IPSPACE))
        self.mock_object(self.library,
                         '_setup_network_for_vserver',
                         mock.Mock(side_effect=network_exception))
        self.mock_object(self.library, '_delete_vserver')

        self.assertRaises(network_exception,
                          self.library._create_vserver,
                          vserver_name,
                          fake.NETWORK_INFO,
                          fake.NFS_CONFIG_TCP_UDP_MAX)

        self.library._get_api_client.assert_called_with(vserver=vserver_name)
        self.assertTrue(self.library._client.create_vserver.called)
        self.library._setup_network_for_vserver.assert_called_with(
            vserver_name,
            vserver_client,
            fake.NETWORK_INFO,
            fake.IPSPACE,
            security_services=security_service,
            nfs_config=None)
        self.library._delete_vserver.assert_called_once_with(
            vserver_name,
            needs_lock=False,
            security_services=security_service)
        self.assertFalse(vserver_client.enable_nfs.called)
        self.assertEqual(1, lib_multi_svm.LOG.error.call_count)

    def test_get_valid_ipspace_name(self):

        result = self.library._get_valid_ipspace_name(fake.IPSPACE_ID)

        expected = 'ipspace_' + fake.IPSPACE_ID.replace('-', '_')
        self.assertEqual(expected, result)

    def test_create_ipspace_not_supported(self):

        self.library._client.features.IPSPACES = False

        result = self.library._create_ipspace(fake.NETWORK_INFO)

        self.assertIsNone(result)

    @ddt.data(None, 'flat')
    def test_create_ipspace_not_vlan(self, network_type):

        self.library._client.features.IPSPACES = True
        network_info = copy.deepcopy(fake.NETWORK_INFO)
        network_info['network_allocations'][0]['segmentation_id'] = None
        network_info['network_allocations'][0]['network_type'] = network_type

        result = self.library._create_ipspace(network_info)

        self.assertEqual('Default', result)

    def test_create_ipspace(self):

        self.library._client.features.IPSPACES = True
        self.mock_object(self.library._client,
                         'create_ipspace',
                         mock.Mock(return_value=False))

        result = self.library._create_ipspace(fake.NETWORK_INFO)

        expected = self.library._get_valid_ipspace_name(
            fake.NETWORK_INFO['neutron_subnet_id'])
        self.assertEqual(expected, result)
        self.library._client.create_ipspace.assert_called_once_with(expected)

    def test_create_vserver_lifs(self):

        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library,
                         '_get_lif_name',
                         mock.Mock(side_effect=['fake_lif1', 'fake_lif2']))
        self.mock_object(self.library, '_create_lif')

        self.library._create_vserver_lifs(fake.VSERVER1,
                                          'fake_vserver_client',
                                          fake.NETWORK_INFO,
                                          fake.IPSPACE)

        self.library._create_lif.assert_has_calls([
            mock.call('fake_vserver_client', fake.VSERVER1, fake.IPSPACE,
                      fake.CLUSTER_NODES[0], 'fake_lif1',
                      fake.NETWORK_INFO['network_allocations'][0]),
            mock.call('fake_vserver_client', fake.VSERVER1, fake.IPSPACE,
                      fake.CLUSTER_NODES[1], 'fake_lif2',
                      fake.NETWORK_INFO['network_allocations'][1])])

    def test_create_vserver_admin_lif(self):

        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library,
                         '_get_lif_name',
                         mock.Mock(return_value='fake_admin_lif'))
        self.mock_object(self.library, '_create_lif')

        self.library._create_vserver_admin_lif(fake.VSERVER1,
                                               'fake_vserver_client',
                                               fake.NETWORK_INFO,
                                               fake.IPSPACE)

        self.library._create_lif.assert_has_calls([
            mock.call('fake_vserver_client', fake.VSERVER1, fake.IPSPACE,
                      fake.CLUSTER_NODES[0], 'fake_admin_lif',
                      fake.NETWORK_INFO['admin_network_allocations'][0])])

    def test_create_vserver_admin_lif_no_admin_network(self):

        fake_network_info = copy.deepcopy(fake.NETWORK_INFO)
        fake_network_info['admin_network_allocations'] = []

        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library,
                         '_get_lif_name',
                         mock.Mock(return_value='fake_admin_lif'))
        self.mock_object(self.library, '_create_lif')

        self.library._create_vserver_admin_lif(fake.VSERVER1,
                                               'fake_vserver_client',
                                               fake_network_info,
                                               fake.IPSPACE)

        self.assertFalse(self.library._create_lif.called)

    @ddt.data(
        fake.get_network_info(fake.USER_NETWORK_ALLOCATIONS,
                              fake.ADMIN_NETWORK_ALLOCATIONS),
        fake.get_network_info(fake.USER_NETWORK_ALLOCATIONS_IPV6,
                              fake.ADMIN_NETWORK_ALLOCATIONS))
    def test_create_vserver_routes(self, network_info):
        expected_gateway = network_info['network_allocations'][0]['gateway']
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'create_route')

        retval = self.library._create_vserver_routes(
            vserver_client, network_info)

        self.assertIsNone(retval)
        vserver_client.create_route.assert_called_once_with(expected_gateway)

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

    def test_get_lif_name(self):

        result = self.library._get_lif_name(
            'fake_node', fake.NETWORK_INFO['network_allocations'][0])

        self.assertEqual('os_132dbb10-9a36-46f2-8d89-3d909830c356', result)

    @ddt.data(fake.MTU, None, 'not-present')
    def test_create_lif(self, mtu):
        """Tests cases where MTU is a valid value, None or not present."""

        expected_mtu = (mtu if mtu not in (None, 'not-present') else
                        fake.DEFAULT_MTU)

        network_allocations = copy.deepcopy(
            fake.NETWORK_INFO['network_allocations'][0])
        network_allocations['mtu'] = mtu

        if mtu == 'not-present':
            network_allocations.pop('mtu')

        vserver_client = mock.Mock()
        vserver_client.network_interface_exists = mock.Mock(
            return_value=False)
        self.mock_object(self.library,
                         '_get_node_data_port',
                         mock.Mock(return_value='fake_port'))

        self.library._create_lif(vserver_client,
                                 'fake_vserver',
                                 'fake_ipspace',
                                 'fake_node',
                                 'fake_lif',
                                 network_allocations)

        self.library._client.create_network_interface.assert_has_calls([
            mock.call('10.10.10.10', '255.255.255.0', '1000', 'fake_node',
                      'fake_port', 'fake_vserver', 'fake_lif',
                      'fake_ipspace', expected_mtu)])

    def test_create_lif_if_nonexistent_already_present(self):

        vserver_client = mock.Mock()
        vserver_client.network_interface_exists = mock.Mock(
            return_value=True)
        self.mock_object(self.library,
                         '_get_node_data_port',
                         mock.Mock(return_value='fake_port'))

        self.library._create_lif(vserver_client,
                                 'fake_vserver',
                                 fake.IPSPACE,
                                 'fake_node',
                                 'fake_lif',
                                 fake.NETWORK_INFO['network_allocations'][0])

        self.assertFalse(self.library._client.create_network_interface.called)

    def test_get_network_allocations_number(self):

        self.library._client.list_cluster_nodes.return_value = (
            fake.CLUSTER_NODES)

        result = self.library.get_network_allocations_number()

        self.assertEqual(len(fake.CLUSTER_NODES), result)

    def test_get_admin_network_allocations_number(self):

        result = self.library.get_admin_network_allocations_number(
            'fake_admin_network_api')

        self.assertEqual(1, result)

    def test_get_admin_network_allocations_number_no_admin_network(self):

        result = self.library.get_admin_network_allocations_number(None)

        self.assertEqual(0, result)

    def test_teardown_server(self):

        self.library._client.vserver_exists.return_value = True
        mock_delete_vserver = self.mock_object(self.library,
                                               '_delete_vserver')

        self.library.teardown_server(
            fake.SHARE_SERVER['backend_details'],
            security_services=fake.NETWORK_INFO['security_services'])

        self.library._client.vserver_exists.assert_called_once_with(
            fake.VSERVER1)
        mock_delete_vserver.assert_called_once_with(
            fake.VSERVER1,
            security_services=fake.NETWORK_INFO['security_services'])

    @ddt.data(None, {}, {'vserver_name': None})
    def test_teardown_server_no_share_server(self, server_details):

        mock_delete_vserver = self.mock_object(self.library,
                                               '_delete_vserver')

        self.library.teardown_server(server_details)

        self.assertFalse(mock_delete_vserver.called)
        self.assertTrue(lib_multi_svm.LOG.warning.called)

    def test_teardown_server_no_vserver(self):

        self.library._client.vserver_exists.return_value = False
        mock_delete_vserver = self.mock_object(self.library,
                                               '_delete_vserver')

        self.library.teardown_server(
            fake.SHARE_SERVER['backend_details'],
            security_services=fake.NETWORK_INFO['security_services'])

        self.library._client.vserver_exists.assert_called_once_with(
            fake.VSERVER1)
        self.assertFalse(mock_delete_vserver.called)
        self.assertTrue(lib_multi_svm.LOG.warning.called)

    @ddt.data(True, False)
    def test_delete_vserver_no_ipspace(self, lock):

        self.mock_object(self.library._client,
                         'get_vserver_ipspace',
                         mock.Mock(return_value=None))
        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        self.mock_object(self.library._client,
                         'get_snapmirror_policies',
                         mock.Mock(return_value=[]))
        mock_delete_vserver_vlans = self.mock_object(self.library,
                                                     '_delete_vserver_vlans')

        net_interfaces = copy.deepcopy(c_fake.NETWORK_INTERFACES_MULTIPLE)
        net_interfaces_with_vlans = [net_interfaces[0]]

        self.mock_object(vserver_client,
                         'get_network_interfaces',
                         mock.Mock(return_value=net_interfaces))
        security_services = fake.NETWORK_INFO['security_services']
        self.mock_object(self.library, '_delete_vserver_peers')

        self.library._delete_vserver(fake.VSERVER1,
                                     security_services=security_services,
                                     needs_lock=lock)

        self.library._client.get_vserver_ipspace.assert_called_once_with(
            fake.VSERVER1)
        self.library._delete_vserver_peers.assert_called_once_with(
            fake.VSERVER1)
        self.library._client.delete_vserver.assert_called_once_with(
            fake.VSERVER1, vserver_client, security_services=security_services)
        self.assertFalse(self.library._client.delete_ipspace.called)
        mock_delete_vserver_vlans.assert_called_once_with(
            net_interfaces_with_vlans)

    @ddt.data(True, False)
    def test_delete_vserver_ipspace_has_data_vservers(self, lock):

        self.mock_object(self.library._client,
                         'get_vserver_ipspace',
                         mock.Mock(return_value=fake.IPSPACE))
        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        self.mock_object(self.library._client,
                         'ipspace_has_data_vservers',
                         mock.Mock(return_value=True))
        self.mock_object(self.library._client,
                         'get_snapmirror_policies',
                         mock.Mock(return_value=[]))
        self.mock_object(self.library, '_delete_vserver_peers')
        self.mock_object(
            vserver_client, 'get_network_interfaces',
            mock.Mock(return_value=c_fake.NETWORK_INTERFACES_MULTIPLE))
        security_services = fake.NETWORK_INFO['security_services']

        self.library._delete_vserver(fake.VSERVER1,
                                     security_services=security_services,
                                     needs_lock=lock)

        self.library._client.get_vserver_ipspace.assert_called_once_with(
            fake.VSERVER1)
        self.library._client.delete_vserver.assert_called_once_with(
            fake.VSERVER1, vserver_client, security_services=security_services)
        self.library._delete_vserver_peers.assert_called_once_with(
            fake.VSERVER1)
        self.assertFalse(self.library._client.delete_ipspace.called)

    @ddt.data([], c_fake.NETWORK_INTERFACES)
    def test_delete_vserver_with_ipspace(self, interfaces):

        self.mock_object(self.library._client,
                         'get_vserver_ipspace',
                         mock.Mock(return_value=fake.IPSPACE))
        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_api_client',
                         mock.Mock(return_value=vserver_client))
        self.mock_object(self.library._client,
                         'ipspace_has_data_vservers',
                         mock.Mock(return_value=False))
        mock_delete_vserver_vlans = self.mock_object(self.library,
                                                     '_delete_vserver_vlans')
        self.mock_object(self.library, '_delete_vserver_peers')
        self.mock_object(vserver_client,
                         'get_network_interfaces',
                         mock.Mock(return_value=interfaces))
        self.mock_object(self.library._client,
                         'get_snapmirror_policies',
                         mock.Mock(return_value=['fake_policy']))

        security_services = fake.NETWORK_INFO['security_services']

        self.library._delete_vserver(fake.VSERVER1,
                                     security_services=security_services)
        vserver_client.delete_snapmirror_policy.assert_called_once_with(
            'fake_policy')
        self.library._delete_vserver_peers.assert_called_once_with(
            fake.VSERVER1
        )
        self.library._client.get_vserver_ipspace.assert_called_once_with(
            fake.VSERVER1)
        self.library._client.delete_vserver.assert_called_once_with(
            fake.VSERVER1, vserver_client, security_services=security_services)
        self.library._client.delete_ipspace.assert_called_once_with(
            fake.IPSPACE)
        mock_delete_vserver_vlans.assert_called_once_with(interfaces)

    def test__delete_vserver_peers(self):

        self.mock_object(self.library,
                         '_get_vserver_peers',
                         mock.Mock(return_value=fake.VSERVER_PEER))
        self.mock_object(self.library, '_delete_vserver_peer')

        self.library._delete_vserver_peers(fake.VSERVER1)

        self.library._get_vserver_peers.assert_called_once_with(
            vserver=fake.VSERVER1
        )
        self.library._delete_vserver_peer.assert_called_once_with(
            fake.VSERVER_PEER[0]['vserver'],
            fake.VSERVER_PEER[0]['peer-vserver']
        )

    def test_delete_vserver_vlans(self):

        self.library._delete_vserver_vlans(c_fake.NETWORK_INTERFACES)
        for interface in c_fake.NETWORK_INTERFACES:
            home_port = interface['home-port']
            port, vlan = home_port.split('-')
            node = interface['home-node']
            self.library._client.delete_vlan.assert_called_once_with(
                node, port, vlan)

    def test_delete_vserver_vlans_client_error(self):

        mock_exception_log = self.mock_object(lib_multi_svm.LOG, 'exception')
        self.mock_object(
            self.library._client,
            'delete_vlan',
            mock.Mock(side_effect=exception.NetAppException("fake error")))

        self.library._delete_vserver_vlans(c_fake.NETWORK_INTERFACES)
        for interface in c_fake.NETWORK_INTERFACES:
            home_port = interface['home-port']
            port, vlan = home_port.split('-')
            node = interface['home-node']
            self.library._client.delete_vlan.assert_called_once_with(
                node, port, vlan)
            self.assertEqual(1, mock_exception_log.call_count)

    @ddt.data([], [{'vserver': c_fake.VSERVER_NAME,
                    'peer-vserver': c_fake.VSERVER_PEER_NAME,
                    'applications': [
                        {'vserver-peer-application': 'snapmirror'}]
                    }])
    def test_create_replica(self, vserver_peers):
        fake_cluster_name = 'fake_cluster'
        self.mock_object(self.library, '_get_vservers_from_replicas',
                         mock.Mock(return_value=(self.fake_vserver,
                                                 self.fake_new_vserver_name)))
        self.mock_object(self.library, 'find_active_replica',
                         mock.Mock(return_value=self.fake_replica))
        self.mock_object(share_utils, 'extract_host',
                         mock.Mock(side_effect=[self.fake_new_replica_host,
                                                self.fake_replica_host]))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(side_effect=[self.fake_new_client,
                                                self.fake_client]))
        self.mock_object(self.library, '_get_vserver_peers',
                         mock.Mock(return_value=vserver_peers))
        self.mock_object(self.fake_new_client, 'get_cluster_name',
                         mock.Mock(return_value=fake_cluster_name))
        self.mock_object(self.fake_client, 'create_vserver_peer')
        self.mock_object(self.fake_new_client, 'accept_vserver_peer')
        lib_base_model_update = {
            'export_locations': [],
            'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC,
            'access_rules_status': constants.STATUS_ACTIVE,
        }
        self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                         'create_replica',
                         mock.Mock(return_value=lib_base_model_update))

        model_update = self.library.create_replica(
            None, [self.fake_replica], self.fake_new_replica, [], [],
            share_server=None)

        self.assertDictMatch(lib_base_model_update, model_update)
        self.library._get_vservers_from_replicas.assert_called_once_with(
            None, [self.fake_replica], self.fake_new_replica
        )
        self.library.find_active_replica.assert_called_once_with(
            [self.fake_replica]
        )
        self.assertEqual(2, share_utils.extract_host.call_count)
        self.assertEqual(2, data_motion.get_client_for_backend.call_count)
        self.library._get_vserver_peers.assert_called_once_with(
            self.fake_new_vserver_name, self.fake_vserver
        )
        self.fake_new_client.get_cluster_name.assert_called_once_with()
        if not vserver_peers:
            self.fake_client.create_vserver_peer.assert_called_once_with(
                self.fake_new_vserver_name, self.fake_vserver,
                peer_cluster_name=fake_cluster_name
            )
            self.fake_new_client.accept_vserver_peer.assert_called_once_with(
                self.fake_vserver, self.fake_new_vserver_name
            )
        base_class = lib_base.NetAppCmodeFileStorageLibrary
        base_class.create_replica.assert_called_once_with(
            None, [self.fake_replica], self.fake_new_replica, [], []
        )

    def test_delete_replica(self):
        base_class = lib_base.NetAppCmodeFileStorageLibrary
        vserver_peers = copy.deepcopy(fake.VSERVER_PEER)
        vserver_peers[0]['vserver'] = self.fake_vserver
        vserver_peers[0]['peer-vserver'] = self.fake_new_vserver_name
        self.mock_object(self.library, '_get_vservers_from_replicas',
                         mock.Mock(return_value=(self.fake_vserver,
                                                 self.fake_new_vserver_name)))
        self.mock_object(base_class, 'delete_replica')
        self.mock_object(self.library, '_get_snapmirrors',
                         mock.Mock(return_value=[]))
        self.mock_object(self.library, '_get_vserver_peers',
                         mock.Mock(return_value=vserver_peers))
        self.mock_object(self.library, '_delete_vserver_peer')

        self.library.delete_replica(None, [self.fake_replica],
                                    self.fake_new_replica, [],
                                    share_server=None)

        self.library._get_vservers_from_replicas.assert_called_once_with(
            None, [self.fake_replica], self.fake_new_replica
        )
        base_class.delete_replica.assert_called_once_with(
            None, [self.fake_replica], self.fake_new_replica, []
        )
        self.library._get_snapmirrors.assert_has_calls(
            [mock.call(self.fake_vserver, self.fake_new_vserver_name),
             mock.call(self.fake_new_vserver_name, self.fake_vserver)]
        )
        self.library._get_vserver_peers.assert_called_once_with(
            self.fake_new_vserver_name, self.fake_vserver
        )
        self.library._delete_vserver_peer.assert_called_once_with(
            self.fake_new_vserver_name, self.fake_vserver
        )

    def test_get_vservers_from_replicas(self):
        self.mock_object(self.library, 'find_active_replica',
                         mock.Mock(return_value=self.fake_replica))

        vserver, peer_vserver = self.library._get_vservers_from_replicas(
            None, [self.fake_replica], self.fake_new_replica)

        self.library.find_active_replica.assert_called_once_with(
            [self.fake_replica]
        )
        self.assertEqual(self.fake_vserver, vserver)
        self.assertEqual(self.fake_new_vserver_name, peer_vserver)

    def test_get_vserver_peers(self):
        self.mock_object(self.library._client, 'get_vserver_peers')

        self.library._get_vserver_peers(
            vserver=self.fake_vserver, peer_vserver=self.fake_new_vserver_name)

        self.library._client.get_vserver_peers.assert_called_once_with(
            self.fake_vserver, self.fake_new_vserver_name
        )

    def test_create_vserver_peer(self):
        self.mock_object(self.library._client, 'create_vserver_peer')

        self.library._create_vserver_peer(
            None, vserver=self.fake_vserver,
            peer_vserver=self.fake_new_vserver_name)

        self.library._client.create_vserver_peer.assert_called_once_with(
            self.fake_vserver, self.fake_new_vserver_name
        )

    def test_delete_vserver_peer(self):
        self.mock_object(self.library._client, 'delete_vserver_peer')

        self.library._delete_vserver_peer(
            vserver=self.fake_vserver, peer_vserver=self.fake_new_vserver_name)

        self.library._client.delete_vserver_peer.assert_called_once_with(
            self.fake_vserver, self.fake_new_vserver_name
        )

    def test_create_share_from_snaphot(self):
        fake_parent_share = copy.deepcopy(fake.SHARE)
        fake_parent_share['id'] = fake.SHARE_ID2
        mock_create_from_snap = self.mock_object(
            lib_base.NetAppCmodeFileStorageLibrary,
            'create_share_from_snapshot')

        self.library.create_share_from_snapshot(
            None, fake.SHARE, fake.SNAPSHOT, share_server=fake.SHARE_SERVER,
            parent_share=fake_parent_share)

        mock_create_from_snap.assert_called_once_with(
            None, fake.SHARE, fake.SNAPSHOT, share_server=fake.SHARE_SERVER,
            parent_share=fake_parent_share
        )

    @ddt.data(
        {'src_cluster_name': fake.CLUSTER_NAME,
         'dest_cluster_name': fake.CLUSTER_NAME, 'has_vserver_peers': None},
        {'src_cluster_name': fake.CLUSTER_NAME,
         'dest_cluster_name': fake.CLUSTER_NAME_2, 'has_vserver_peers': False},
        {'src_cluster_name': fake.CLUSTER_NAME,
         'dest_cluster_name': fake.CLUSTER_NAME_2, 'has_vserver_peers': True}
    )
    @ddt.unpack
    def test_create_share_from_snaphot_different_hosts(self, src_cluster_name,
                                                       dest_cluster_name,
                                                       has_vserver_peers):
        class FakeDBObj(dict):
            def to_dict(self):
                return self
        fake_parent_share = copy.deepcopy(fake.SHARE)
        fake_parent_share['id'] = fake.SHARE_ID2
        fake_parent_share['host'] = fake.MANILA_HOST_NAME_2
        fake_share = FakeDBObj(fake.SHARE)
        fake_share_server = FakeDBObj(fake.SHARE_SERVER)
        src_vserver = fake.VSERVER2
        dest_vserver = fake.VSERVER1
        src_backend = fake.BACKEND_NAME
        dest_backend = fake.BACKEND_NAME_2
        mock_dm_session = mock.Mock()

        mock_dm_constr = self.mock_object(
            data_motion, "DataMotionSession",
            mock.Mock(return_value=mock_dm_session))
        mock_get_vserver = self.mock_object(
            mock_dm_session, 'get_vserver_from_share',
            mock.Mock(side_effect=[src_vserver, dest_vserver]))
        src_vserver_client = mock.Mock()
        dest_vserver_client = mock.Mock()
        mock_extract_host = self.mock_object(
            share_utils, 'extract_host',
            mock.Mock(side_effect=[src_backend, dest_backend]))
        mock_dm_get_client = self.mock_object(
            data_motion, 'get_client_for_backend',
            mock.Mock(side_effect=[src_vserver_client, dest_vserver_client]))
        mock_get_src_cluster_name = self.mock_object(
            src_vserver_client, 'get_cluster_name',
            mock.Mock(return_value=src_cluster_name))
        mock_get_dest_cluster_name = self.mock_object(
            dest_vserver_client, 'get_cluster_name',
            mock.Mock(return_value=dest_cluster_name))
        mock_get_vserver_peers = self.mock_object(
            self.library, '_get_vserver_peers',
            mock.Mock(return_value=has_vserver_peers))
        mock_create_vserver_peer = self.mock_object(dest_vserver_client,
                                                    'create_vserver_peer')
        mock_accept_peer = self.mock_object(src_vserver_client,
                                            'accept_vserver_peer')
        mock_create_from_snap = self.mock_object(
            lib_base.NetAppCmodeFileStorageLibrary,
            'create_share_from_snapshot')

        self.library.create_share_from_snapshot(
            None, fake_share, fake.SNAPSHOT, share_server=fake_share_server,
            parent_share=fake_parent_share)

        internal_share = copy.deepcopy(fake.SHARE)
        internal_share['share_server'] = copy.deepcopy(fake.SHARE_SERVER)

        mock_dm_constr.assert_called_once()
        mock_get_vserver.assert_has_calls([mock.call(fake_parent_share),
                                           mock.call(internal_share)])
        mock_extract_host.assert_has_calls([
            mock.call(fake_parent_share['host'], level='backend_name'),
            mock.call(internal_share['host'], level='backend_name')])
        mock_dm_get_client.assert_has_calls([
            mock.call(src_backend, vserver_name=src_vserver),
            mock.call(dest_backend, vserver_name=dest_vserver)
        ])
        mock_get_src_cluster_name.assert_called_once()
        mock_get_dest_cluster_name.assert_called_once()
        if src_cluster_name != dest_cluster_name:
            mock_get_vserver_peers.assert_called_once_with(dest_vserver,
                                                           src_vserver)
            if not has_vserver_peers:
                mock_create_vserver_peer.assert_called_once_with(
                    dest_vserver, src_vserver,
                    peer_cluster_name=src_cluster_name)
                mock_accept_peer.assert_called_once_with(src_vserver,
                                                         dest_vserver)
        mock_create_from_snap.assert_called_once_with(
            None, fake.SHARE, fake.SNAPSHOT, share_server=fake.SHARE_SERVER,
            parent_share=fake_parent_share)

    def test_check_if_extra_spec_is_positive_with_negative_integer(self):
        self.assertRaises(exception.NetAppException,
                          self.library._check_if_max_files_is_valid,
                          fake.SHARE, -1)

    def test_check_if_extra_spec_is_positive_with_string(self):
        self.assertRaises(ValueError,
                          self.library._check_if_max_files_is_valid,
                          fake.SHARE, 'abc')

    def test_check_nfs_config_extra_specs_validity(self):
        result = self.library._check_nfs_config_extra_specs_validity(
            fake.EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_nfs_config_extra_specs_validity_empty_spec(self):
        result = self.library._check_nfs_config_extra_specs_validity({})

        self.assertIsNone(result)

    @ddt.data(fake.INVALID_TCP_MAX_XFER_SIZE_EXTRA_SPEC,
              fake.INVALID_UDP_MAX_XFER_SIZE_EXTRA_SPEC)
    def test_check_nfs_config_extra_specs_validity_invalid_value(self,
                                                                 extra_specs):
        self.assertRaises(
            exception.NetAppException,
            self.library._check_nfs_config_extra_specs_validity,
            extra_specs)

    @ddt.data({}, fake.STRING_EXTRA_SPEC)
    def test_get_nfs_config_provisioning_options_empty(self, extra_specs):
        result = self.library._get_nfs_config_provisioning_options(
            extra_specs)

        self.assertDictEqual(result, fake.NFS_CONFIG_DEFAULT)

    @ddt.data(
        {'extra_specs': fake.NFS_CONFIG_TCP_MAX_DDT['extra_specs'],
         'expected': fake.NFS_CONFIG_TCP_MAX_DDT['expected']},
        {'extra_specs': fake.NFS_CONFIG_UDP_MAX_DDT['extra_specs'],
         'expected': fake.NFS_CONFIG_UDP_MAX_DDT['expected']},
        {'extra_specs': fake.NFS_CONFIG_TCP_UDP_MAX_DDT['extra_specs'],
         'expected': fake.NFS_CONFIG_TCP_UDP_MAX_DDT['expected']},
    )
    @ddt.unpack
    def test_get_nfs_config_provisioning_options_valid(self, extra_specs,
                                                       expected):
        result = self.library._get_nfs_config_provisioning_options(
            extra_specs)

        self.assertDictEqual(expected, result)

    @ddt.data({'fake_share_server': fake.SHARE_SERVER_NFS_TCP,
               'expected_nfs_config': fake.NFS_CONFIG_TCP_MAX},
              {'fake_share_server': fake.SHARE_SERVER_NFS_UDP,
               'expected_nfs_config': fake.NFS_CONFIG_UDP_MAX},
              {'fake_share_server': fake.SHARE_SERVER_NFS_TCP_UDP,
               'expected_nfs_config': fake.NFS_CONFIG_TCP_UDP_MAX},
              {'fake_share_server': fake.SHARE_SERVER_NO_DETAILS,
               'expected_nfs_config': fake.NFS_CONFIG_DEFAULT},
              {'fake_share_server': fake.SHARE_SERVER_NFS_DEFAULT,
               'expected_nfs_config': None},
              {'fake_share_server': fake.SHARE_SERVER_NO_NFS_NONE,
               'expected_nfs_config': fake.NFS_CONFIG_DEFAULT})
    @ddt.unpack
    def test_is_share_server_compatible_true(self, fake_share_server,
                                             expected_nfs_config):
        is_same = self.library._is_share_server_compatible(
            fake_share_server, expected_nfs_config)
        self.assertTrue(is_same)

    @ddt.data({'fake_share_server': fake.SHARE_SERVER_NFS_TCP,
               'expected_nfs_config': fake.NFS_CONFIG_UDP_MAX},
              {'fake_share_server': fake.SHARE_SERVER_NFS_UDP,
               'expected_nfs_config': fake.NFS_CONFIG_TCP_MAX},
              {'fake_share_server': fake.SHARE_SERVER_NFS_TCP_UDP,
               'expected_nfs_config': fake.NFS_CONFIG_TCP_MAX},
              {'fake_share_server': fake.SHARE_SERVER_NFS_TCP_UDP,
               'expected_nfs_config': fake.NFS_CONFIG_UDP_MAX},
              {'fake_share_server': fake.SHARE_SERVER_NFS_TCP_UDP,
               'expected_nfs_config': None},
              {'fake_share_server': fake.SHARE_SERVER_NFS_TCP_UDP,
               'expected_nfs_config': {}},
              {'fake_share_server': fake.SHARE_SERVER_NFS_TCP_UDP,
               'expected_nfs_config': fake.NFS_CONFIG_DEFAULT},
              {'fake_share_server': fake.SHARE_SERVER_NO_DETAILS,
               'expected_nfs_config': fake.NFS_CONFIG_UDP_MAX},
              {'fake_share_server': fake.SHARE_SERVER_NFS_DEFAULT,
               'expected_nfs_config': fake.NFS_CONFIG_UDP_MAX},
              {'fake_share_server': fake.SHARE_SERVER_NO_NFS_NONE,
               'expected_nfs_config': fake.NFS_CONFIG_TCP_MAX})
    @ddt.unpack
    def test_is_share_server_compatible_false(self, fake_share_server,
                                              expected_nfs_config):
        is_same = self.library._is_share_server_compatible(
            fake_share_server, expected_nfs_config)
        self.assertFalse(is_same)

    @ddt.data(
        {'expected_server': fake.SHARE_SERVER_NFS_TCP,
         'share_group': {'share_server_id': fake.SHARE_SERVER_NFS_TCP['id']},
         'nfs_config': fake.NFS_CONFIG_TCP_MAX},
        {'expected_server': fake.SHARE_SERVER_NFS_UDP,
         'share_group': {'share_server_id': fake.SHARE_SERVER_NFS_UDP['id']},
         'nfs_config': fake.NFS_CONFIG_UDP_MAX},
        {'expected_server': fake.SHARE_SERVER_NFS_TCP_UDP,
         'share_group': {
             'share_server_id': fake.SHARE_SERVER_NFS_TCP_UDP['id']},
         'nfs_config': fake.NFS_CONFIG_TCP_UDP_MAX},
        {'expected_server': fake.SHARE_SERVER_NFS_DEFAULT,
         'share_group': {
             'share_server_id': fake.SHARE_SERVER_NFS_DEFAULT['id']},
         'nfs_config': fake.NFS_CONFIG_DEFAULT},
        {'expected_server': None,
         'share_group': {'share_server_id': 'invalid_id'},
         'nfs_config': fake.NFS_CONFIG_TCP_MAX})
    @ddt.unpack
    def test_choose_share_server_compatible_with_share_group_and_nfs_config(
            self, expected_server, share_group, nfs_config):
        self.library.is_nfs_config_supported = True
        mock_get_extra_spec = self.mock_object(
            share_types, "get_extra_specs_from_share",
            mock.Mock(return_value=fake.EXTRA_SPEC))
        mock_get_nfs_config = self.mock_object(
            self.library,
            "_get_nfs_config_provisioning_options",
            mock.Mock(return_value=nfs_config))
        mock_client = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=('fake_name',
                                                 mock_client)))
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))

        server = self.library.choose_share_server_compatible_with_share(
            None, fake.SHARE_SERVERS, fake.SHARE, None, share_group)

        mock_get_extra_spec.assert_called_once_with(fake.SHARE)
        mock_get_nfs_config.assert_called_once_with(fake.EXTRA_SPEC)
        self.assertEqual(expected_server, server)

    @ddt.data(
        {'expected_server': fake.SHARE_SERVER_NO_NFS_NONE,
         'share_group': {'share_server_id':
                         fake.SHARE_SERVER_NO_NFS_NONE['id']}},
        {'expected_server': fake.SHARE_SERVER_NO_DETAILS,
         'share_group': {'share_server_id':
                         fake.SHARE_SERVER_NO_DETAILS['id']}},
        {'expected_server': fake.SHARE_SERVER_NO_DETAILS,
         'share_group': {
             'share_server_id': fake.SHARE_SERVER_NO_DETAILS['id']},
         'nfs_config_support': False},
        {'expected_server': None,
         'share_group': {'share_server_id': 'invalid_id'}})
    @ddt.unpack
    def test_choose_share_server_compatible_with_share_group_only(
            self, expected_server, share_group, nfs_config_support=True):
        self.library.is_nfs_config_supported = nfs_config_support
        mock_get_extra_spec = self.mock_object(
            share_types, "get_extra_specs_from_share",
            mock.Mock(return_value=fake.EMPTY_EXTRA_SPEC))
        mock_get_nfs_config = self.mock_object(
            self.library,
            "_get_nfs_config_provisioning_options",
            mock.Mock(return_value=fake.NFS_CONFIG_DEFAULT))
        mock_client = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=('fake_name',
                                                 mock_client)))
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))

        server = self.library.choose_share_server_compatible_with_share(
            None, fake.SHARE_SERVERS, fake.SHARE, None, share_group)

        self.assertEqual(expected_server, server)
        if nfs_config_support:
            mock_get_extra_spec.assert_called_once_with(fake.SHARE)
            mock_get_nfs_config.assert_called_once_with(fake.EMPTY_EXTRA_SPEC)

    @ddt.data(
        {'expected_server': fake.SHARE_SERVER_NFS_TCP,
         'nfs_config': fake.NFS_CONFIG_TCP_MAX},
        {'expected_server': fake.SHARE_SERVER_NFS_UDP,
         'nfs_config': fake.NFS_CONFIG_UDP_MAX},
        {'expected_server': fake.SHARE_SERVER_NFS_TCP_UDP,
         'nfs_config': fake.NFS_CONFIG_TCP_UDP_MAX},
        {'expected_server': fake.SHARE_SERVER_NFS_DEFAULT,
         'nfs_config': fake.NFS_CONFIG_DEFAULT},
        {'expected_server': None,
         'nfs_config': {'invalid': 'invalid'}},
        {'expected_server': fake.SHARE_SERVER_NFS_TCP,
         'nfs_config': None, 'nfs_config_support': False},
    )
    @ddt.unpack
    def test_choose_share_server_compatible_with_share_nfs_config_only(
            self, expected_server, nfs_config, nfs_config_support=True):
        self.library.is_nfs_config_supported = nfs_config_support
        mock_get_extra_spec = self.mock_object(
            share_types, "get_extra_specs_from_share",
            mock.Mock(return_value=fake.EXTRA_SPEC))
        mock_get_nfs_config = self.mock_object(
            self.library,
            "_get_nfs_config_provisioning_options",
            mock.Mock(return_value=nfs_config))
        mock_client = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=('fake_name',
                                                 mock_client)))
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))

        server = self.library.choose_share_server_compatible_with_share(
            None, fake.SHARE_SERVERS, fake.SHARE)

        self.assertEqual(expected_server, server)
        if nfs_config_support:
            mock_get_extra_spec.assert_called_once_with(fake.SHARE)
            mock_get_nfs_config.assert_called_once_with(fake.EXTRA_SPEC)

    @ddt.data(
        {'expected_server': fake.SHARE_SERVER_NO_DETAILS,
         'share_servers': [
             fake.SHARE_SERVER_NFS_TCP, fake.SHARE_SERVER_NO_DETAILS]},
        {'expected_server': fake.SHARE_SERVER_NO_NFS_NONE,
         'share_servers': [
             fake.SHARE_SERVER_NFS_UDP, fake.SHARE_SERVER_NO_NFS_NONE]},
        {'expected_server': fake.SHARE_SERVER_NFS_DEFAULT,
         'share_servers': [
             fake.SHARE_SERVER_NFS_UDP, fake.SHARE_SERVER_NFS_DEFAULT]},
        {'expected_server': None,
         'share_servers': [
             fake.SHARE_SERVER_NFS_TCP, fake.SHARE_SERVER_NFS_UDP]},
        {'expected_server': fake.SHARE_SERVER_NO_DETAILS,
         'share_servers': [fake.SHARE_SERVER_NO_DETAILS],
         'nfs_config_support': False}
    )
    @ddt.unpack
    def test_choose_share_server_compatible_with_share_no_specification(
            self, expected_server, share_servers, nfs_config_support=True):
        self.library.is_nfs_config_supported = nfs_config_support
        mock_get_extra_spec = self.mock_object(
            share_types, "get_extra_specs_from_share",
            mock.Mock(return_value=fake.EMPTY_EXTRA_SPEC))
        mock_get_nfs_config = self.mock_object(
            self.library,
            "_get_nfs_config_provisioning_options",
            mock.Mock(return_value=fake.NFS_CONFIG_DEFAULT))
        mock_client = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=('fake_name',
                                                 mock_client)))
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))

        server = self.library.choose_share_server_compatible_with_share(
            None, share_servers, fake.SHARE)

        self.assertEqual(expected_server, server)
        if nfs_config_support:
            mock_get_extra_spec.assert_called_once_with(fake.SHARE)
            mock_get_nfs_config.assert_called_once_with(fake.EMPTY_EXTRA_SPEC)

    def test_manage_existing_error(self):
        fake_server = {'id': 'id'}
        fake_nfs_config = 'fake_nfs_config'
        self.library.is_nfs_config_supported = True

        mock_get_extra_spec = self.mock_object(
            share_types, "get_extra_specs_from_share",
            mock.Mock(return_value=fake.EXTRA_SPEC))
        mock_get_nfs_config = self.mock_object(
            self.library,
            "_get_nfs_config_provisioning_options",
            mock.Mock(return_value=fake_nfs_config))
        mock_is_compatible = self.mock_object(
            self.library,
            "_is_share_server_compatible",
            mock.Mock(return_value=False))

        self.assertRaises(exception.NetAppException,
                          self.library.manage_existing,
                          fake.SHARE, 'opts', fake_server)

        mock_get_extra_spec.assert_called_once_with(fake.SHARE)
        mock_get_nfs_config.assert_called_once_with(fake.EXTRA_SPEC)
        mock_is_compatible.assert_called_once_with(fake_server,
                                                   fake_nfs_config)

    def test_choose_share_server_compatible_with_share_group_no_share_server(
            self):
        server = self.library.choose_share_server_compatible_with_share_group(
            None, [], fake.SHARE_GROUP_REF)

        self.assertIsNone(server)

    @ddt.data(
        [fake.NFS_CONFIG_DEFAULT, fake.NFS_CONFIG_TCP_MAX],
        [fake.NFS_CONFIG_TCP_MAX, fake.NFS_CONFIG_UDP_MAX],
        [fake.NFS_CONFIG_TCP_UDP_MAX, fake.NFS_CONFIG_TCP_MAX],
        [fake.NFS_CONFIG_DEFAULT, fake.NFS_CONFIG_TCP_UDP_MAX])
    def test_choose_share_server_compatible_with_share_group_nfs_conflict(
            self, nfs_config_list):
        self.library.is_nfs_config_supported = True
        self.mock_object(
            share_types, "get_share_type_extra_specs",
            mock.Mock(return_value=fake.EXTRA_SPEC))
        mock_get_nfs_config = self.mock_object(
            self.library,
            "_get_nfs_config_provisioning_options",
            mock.Mock(side_effect=nfs_config_list))
        mock_check_extra_spec = self.mock_object(
            self.library,
            '_check_nfs_config_extra_specs_validity',
            mock.Mock())

        self.assertRaises(exception.InvalidInput,
                          self.library.
                          choose_share_server_compatible_with_share_group,
                          None, fake.SHARE_SERVERS, fake.SHARE_GROUP_REF)

        mock_get_nfs_config.assert_called_with(fake.EXTRA_SPEC)
        mock_check_extra_spec.assert_called_once_with(fake.EXTRA_SPEC)

    @ddt.data(
        {'expected_server': fake.SHARE_SERVER_NO_DETAILS,
         'nfs_config': fake.NFS_CONFIG_DEFAULT,
         'share_servers': [
             fake.SHARE_SERVER_NFS_TCP, fake.SHARE_SERVER_NO_DETAILS]},
        {'expected_server': fake.SHARE_SERVER_NO_NFS_NONE,
         'nfs_config': fake.NFS_CONFIG_DEFAULT,
         'share_servers': [
             fake.SHARE_SERVER_NFS_UDP, fake.SHARE_SERVER_NO_NFS_NONE]},
        {'expected_server': fake.SHARE_SERVER_NFS_DEFAULT,
         'nfs_config': fake.NFS_CONFIG_DEFAULT,
         'share_servers': [
             fake.SHARE_SERVER_NFS_UDP, fake.SHARE_SERVER_NFS_DEFAULT]},
        {'expected_server': None,
         'nfs_config': fake.NFS_CONFIG_DEFAULT,
         'share_servers': [
             fake.SHARE_SERVER_NFS_TCP, fake.SHARE_SERVER_NFS_UDP,
             fake.SHARE_SERVER_NFS_TCP_UDP]},
        {'expected_server': fake.SHARE_SERVER_NFS_TCP_UDP,
         'nfs_config': fake.NFS_CONFIG_TCP_UDP_MAX,
         'share_servers': [
             fake.SHARE_SERVER_NFS_TCP, fake.SHARE_SERVER_NFS_UDP,
             fake.SHARE_SERVER_NFS_DEFAULT, fake.SHARE_SERVER_NFS_TCP_UDP]},
        {'expected_server': fake.SHARE_SERVER_NO_DETAILS,
         'nfs_config': None,
         'share_servers': [fake.SHARE_SERVER_NO_DETAILS],
         'nfs_config_supported': False}
    )
    @ddt.unpack
    def test_choose_share_server_compatible_with_share_group_nfs(
            self, expected_server, nfs_config, share_servers,
            nfs_config_supported=True):
        self.library.is_nfs_config_supported = nfs_config_supported
        self.mock_object(
            share_types, "get_share_type_extra_specs",
            mock.Mock(return_value=fake.EXTRA_SPEC))
        mock_get_nfs_config = self.mock_object(
            self.library,
            "_get_nfs_config_provisioning_options",
            mock.Mock(return_value=nfs_config))
        mock_check_extra_spec = self.mock_object(
            self.library,
            '_check_nfs_config_extra_specs_validity',
            mock.Mock())
        mock_client = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=('fake_name',
                                                 mock_client)))
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))

        server = self.library.choose_share_server_compatible_with_share_group(
            None, share_servers, fake.SHARE_GROUP_REF)

        if nfs_config_supported:
            mock_get_nfs_config.assert_called_with(fake.EXTRA_SPEC)
            mock_check_extra_spec.assert_called_once_with(fake.EXTRA_SPEC)
        else:
            mock_get_nfs_config.assert_not_called()
            mock_check_extra_spec.assert_not_called()
        self.assertEqual(expected_server, server)

    def test_share_server_migration_check_compatibility_same_backend(
            self):
        not_compatible = fake.SERVER_MIGRATION_CHECK_NOT_COMPATIBLE
        self.library._have_cluster_creds = True
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(None, None)))

        result = self.library.share_server_migration_check_compatibility(
            None, self.fake_src_share_server,
            self.fake_src_share_server['host'],
            None, None, None)

        self.assertEqual(not_compatible, result)

    def _configure_mocks_share_server_migration_check_compatibility(
            self, have_cluster_creds=True,
            src_cluster_name=fake.CLUSTER_NAME,
            dest_cluster_name=fake.CLUSTER_NAME_2,
            src_svm_dr_support=True, dest_svm_dr_support=True,
            check_capacity_result=True,
            pools=fake.POOLS):
        self.library._have_cluster_creds = have_cluster_creds
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(self.fake_src_vserver,
                                                 self.mock_src_client)))
        self.mock_object(self.mock_src_client, 'get_cluster_name',
                         mock.Mock(return_value=src_cluster_name))
        self.mock_object(self.client, 'get_cluster_name',
                         mock.Mock(return_value=dest_cluster_name))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=self.mock_dest_client))
        self.mock_object(self.mock_src_client, 'is_svm_dr_supported',
                         mock.Mock(return_value=src_svm_dr_support))
        self.mock_object(self.mock_dest_client, 'is_svm_dr_supported',
                         mock.Mock(return_value=dest_svm_dr_support))
        self.mock_object(self.library, '_get_pools',
                         mock.Mock(return_value=pools))
        self.mock_object(self.library, '_check_capacity_compatibility',
                         mock.Mock(return_value=check_capacity_result))

    def test_share_server_migration_check_compatibility_dest_with_pool(
            self):
        not_compatible = fake.SERVER_MIGRATION_CHECK_NOT_COMPATIBLE
        self.library._have_cluster_creds = True

        result = self.library.share_server_migration_check_compatibility(
            None, self.fake_src_share_server, fake.MANILA_HOST_NAME,
            None, None, None)

        self.assertEqual(not_compatible, result)

    def test_share_server_migration_check_compatibility_same_cluster(
            self):
        not_compatible = fake.SERVER_MIGRATION_CHECK_NOT_COMPATIBLE
        self._configure_mocks_share_server_migration_check_compatibility(
            src_cluster_name=fake.CLUSTER_NAME,
            dest_cluster_name=fake.CLUSTER_NAME,
        )

        result = self.library.share_server_migration_check_compatibility(
            None, self.fake_src_share_server,
            self.fake_dest_share_server['host'],
            None, None, None)

        self.assertEqual(not_compatible, result)
        self.library._get_vserver.assert_called_once_with(
            self.fake_src_share_server,
            backend_name=self.fake_src_backend_name
        )
        self.assertTrue(self.mock_src_client.get_cluster_name.called)
        self.assertTrue(self.client.get_cluster_name.called)

    def test_share_server_migration_check_compatibility_svm_dr_not_supported(
            self):
        not_compatible = fake.SERVER_MIGRATION_CHECK_NOT_COMPATIBLE
        self._configure_mocks_share_server_migration_check_compatibility(
            dest_svm_dr_support=False,
        )

        result = self.library.share_server_migration_check_compatibility(
            None, self.fake_src_share_server,
            self.fake_dest_share_server['host'],
            None, None, None)

        self.assertEqual(not_compatible, result)
        self.library._get_vserver.assert_called_once_with(
            self.fake_src_share_server,
            backend_name=self.fake_src_backend_name
        )
        self.assertTrue(self.mock_src_client.get_cluster_name.called)
        self.assertTrue(self.client.get_cluster_name.called)
        data_motion.get_client_for_backend.assert_called_once_with(
            self.fake_dest_backend_name, vserver_name=None
        )
        self.assertTrue(self.mock_src_client.is_svm_dr_supported.called)
        self.assertTrue(self.mock_dest_client.is_svm_dr_supported.called)

    def test_share_server_migration_check_compatibility_different_sec_service(
            self):
        not_compatible = fake.SERVER_MIGRATION_CHECK_NOT_COMPATIBLE
        self._configure_mocks_share_server_migration_check_compatibility()
        new_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        new_sec_service['id'] = 'new_sec_serv_id'
        new_share_network = copy.deepcopy(fake.SHARE_NETWORK)
        new_share_network['id'] = 'fake_share_network_id_2'
        new_share_network['security_services'] = [new_sec_service]

        result = self.library.share_server_migration_check_compatibility(
            None, self.fake_src_share_server,
            self.fake_dest_share_server['host'],
            fake.SHARE_NETWORK, new_share_network, None)

        self.assertEqual(not_compatible, result)
        self.library._get_vserver.assert_called_once_with(
            self.fake_src_share_server,
            backend_name=self.fake_src_backend_name
        )
        self.assertTrue(self.mock_src_client.get_cluster_name.called)
        self.assertTrue(self.client.get_cluster_name.called)
        data_motion.get_client_for_backend.assert_called_once_with(
            self.fake_dest_backend_name, vserver_name=None
        )
        self.assertTrue(self.mock_src_client.is_svm_dr_supported.called)
        self.assertTrue(self.mock_dest_client.is_svm_dr_supported.called)

    @ddt.data('netapp_flexvol_encryption', 'revert_to_snapshot_support')
    def test_share_server_migration_check_compatibility_invalid_capabilities(
            self, capability):
        not_compatible = fake.SERVER_MIGRATION_CHECK_NOT_COMPATIBLE
        pools_without_capability = copy.deepcopy(fake.POOLS)
        for pool in pools_without_capability:
            pool[capability] = False
        self._configure_mocks_share_server_migration_check_compatibility(
            pools=pools_without_capability
        )

        result = self.library.share_server_migration_check_compatibility(
            None, self.fake_src_share_server,
            self.fake_dest_share_server['host'],
            fake.SHARE_NETWORK, fake.SHARE_NETWORK,
            fake.SERVER_MIGRATION_REQUEST_SPEC)

        self.assertEqual(not_compatible, result)
        self.library._get_vserver.assert_called_once_with(
            self.fake_src_share_server,
            backend_name=self.fake_src_backend_name
        )
        self.assertTrue(self.mock_src_client.get_cluster_name.called)
        self.assertTrue(self.client.get_cluster_name.called)
        data_motion.get_client_for_backend.assert_called_once_with(
            self.fake_dest_backend_name, vserver_name=None
        )
        self.assertTrue(self.mock_src_client.is_svm_dr_supported.called)
        self.assertTrue(self.mock_dest_client.is_svm_dr_supported.called)

    def test_share_server_migration_check_compatibility_capacity_false(
            self):
        not_compatible = fake.SERVER_MIGRATION_CHECK_NOT_COMPATIBLE
        self._configure_mocks_share_server_migration_check_compatibility(
            check_capacity_result=False
        )

        result = self.library.share_server_migration_check_compatibility(
            None, self.fake_src_share_server,
            self.fake_dest_share_server['host'],
            fake.SHARE_NETWORK, fake.SHARE_NETWORK,
            fake.SERVER_MIGRATION_REQUEST_SPEC)

        self.assertEqual(not_compatible, result)
        self.library._get_vserver.assert_called_once_with(
            self.fake_src_share_server,
            backend_name=self.fake_src_backend_name
        )
        self.assertTrue(self.mock_src_client.get_cluster_name.called)
        self.assertTrue(self.client.get_cluster_name.called)
        data_motion.get_client_for_backend.assert_called_once_with(
            self.fake_dest_backend_name, vserver_name=None
        )
        self.assertTrue(self.mock_src_client.is_svm_dr_supported.called)
        self.assertTrue(self.mock_dest_client.is_svm_dr_supported.called)
        total_size = (fake.SERVER_MIGRATION_REQUEST_SPEC['shares_size'] +
                      fake.SERVER_MIGRATION_REQUEST_SPEC['snapshots_size'])
        self.library._check_capacity_compatibility.assert_called_once_with(
            fake.POOLS,
            self.library.configuration.max_over_subscription_ratio > 1,
            total_size
        )

    def test_share_server_migration_check_compatibility_compatible(self):
        compatible = {
            'compatible': True,
            'writable': True,
            'nondisruptive': False,
            'preserve_snapshots': True,
            'migration_cancel': True,
            'migration_get_progress': False,
            'share_network_id': fake.SHARE_NETWORK['id']
        }
        self._configure_mocks_share_server_migration_check_compatibility()

        result = self.library.share_server_migration_check_compatibility(
            None, self.fake_src_share_server,
            self.fake_dest_share_server['host'],
            fake.SHARE_NETWORK, fake.SHARE_NETWORK,
            fake.SERVER_MIGRATION_REQUEST_SPEC)

        self.assertEqual(compatible, result)
        self.library._get_vserver.assert_called_once_with(
            self.fake_src_share_server,
            backend_name=self.fake_src_backend_name
        )
        self.assertTrue(self.mock_src_client.get_cluster_name.called)
        self.assertTrue(self.client.get_cluster_name.called)
        data_motion.get_client_for_backend.assert_called_once_with(
            self.fake_dest_backend_name, vserver_name=None
        )
        self.assertTrue(self.mock_src_client.is_svm_dr_supported.called)
        self.assertTrue(self.mock_dest_client.is_svm_dr_supported.called)
        total_size = (fake.SERVER_MIGRATION_REQUEST_SPEC['shares_size'] +
                      fake.SERVER_MIGRATION_REQUEST_SPEC['snapshots_size'])
        self.library._check_capacity_compatibility.assert_called_once_with(
            fake.POOLS,
            self.library.configuration.max_over_subscription_ratio > 1,
            total_size
        )

    @ddt.data({'vserver_peered': True, 'src_cluster': fake.CLUSTER_NAME},
              {'vserver_peered': False, 'src_cluster': fake.CLUSTER_NAME},
              {'vserver_peered': False,
               'src_cluster': fake.CLUSTER_NAME_2})
    @ddt.unpack
    def test_share_server_migration_start(self, vserver_peered,
                                          src_cluster):
        dest_cluster = fake.CLUSTER_NAME
        dm_session_mock = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=[
                             (self.fake_src_vserver, self.mock_src_client),
                             (self.fake_dest_vserver,
                              self.mock_dest_client)]))
        self.mock_object(self.mock_src_client, 'get_cluster_name',
                         mock.Mock(return_value=src_cluster))
        self.mock_object(self.mock_dest_client, 'get_cluster_name',
                         mock.Mock(return_value=dest_cluster))
        self.mock_object(self.library, '_get_vserver_peers',
                         mock.Mock(return_value=vserver_peered))
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))

        self.library.share_server_migration_start(
            None, self.fake_src_share_server, self.fake_dest_share_server,
            [fake.SHARE_INSTANCE], [])

        self.library._get_vserver.assert_has_calls([
            mock.call(share_server=self.fake_src_share_server,
                      backend_name=self.fake_src_backend_name),
            mock.call(share_server=self.fake_dest_share_server,
                      backend_name=self.fake_dest_backend_name)])
        self.assertTrue(self.mock_src_client.get_cluster_name.called)
        self.assertTrue(self.mock_dest_client.get_cluster_name.called)
        self.library._get_vserver_peers.assert_called_once_with(
            self.fake_dest_vserver, self.fake_src_vserver
        )
        mock_vserver_peer = self.mock_dest_client.create_vserver_peer
        if vserver_peered:
            self.assertFalse(mock_vserver_peer.called)
        else:
            mock_vserver_peer.assert_called_once_with(
                self.fake_dest_vserver, self.fake_src_vserver,
                peer_cluster_name=src_cluster
            )
            accept_peer_mock = self.mock_src_client.accept_vserver_peer
            if src_cluster != dest_cluster:
                accept_peer_mock.assert_called_once_with(
                    self.fake_src_vserver, self.fake_dest_vserver
                )
            else:
                self.assertFalse(accept_peer_mock.called)
        dm_session_mock.create_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    def test_share_server_migration_start_snapmirror_start_failure(self):
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=[
                             (self.fake_src_vserver, self.mock_src_client),
                             (self.fake_dest_vserver,
                              self.mock_dest_client)]))
        self.mock_object(self.mock_src_client, 'get_cluster_name')
        self.mock_object(self.mock_dest_client, 'get_cluster_name')
        self.mock_object(self.library, '_get_vserver_peers',
                         mock.Mock(return_value=True))
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        create_snapmirror_mock = self.mock_object(
            dm_session_mock, 'create_snapmirror_svm',
            mock.Mock(
                side_effect=exception.NetAppException(message='fake')))

        self.assertRaises(exception.NetAppException,
                          self.library.share_server_migration_start,
                          None, self.fake_src_share_server,
                          self.fake_dest_share_server,
                          [fake.SHARE_INSTANCE], [])

        self.library._get_vserver.assert_has_calls([
            mock.call(share_server=self.fake_src_share_server,
                      backend_name=self.fake_src_backend_name),
            mock.call(share_server=self.fake_dest_share_server,
                      backend_name=self.fake_dest_backend_name)])
        self.assertTrue(self.mock_src_client.get_cluster_name.called)
        self.assertTrue(self.mock_dest_client.get_cluster_name.called)
        self.library._get_vserver_peers.assert_called_once_with(
            self.fake_dest_vserver, self.fake_src_vserver
        )
        self.assertFalse(self.mock_dest_client.create_vserver_peer.called)

        create_snapmirror_mock.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        dm_session_mock.cancel_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    def test__get_snapmirror_svm(self):
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        fake_snapmirrors = ['mirror1']
        self.mock_object(dm_session_mock, 'get_snapmirrors_svm',
                         mock.Mock(return_value=fake_snapmirrors))

        result = self.library._get_snapmirror_svm(
            self.fake_src_share_server, self.fake_dest_share_server)

        dm_session_mock.get_snapmirrors_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        self.assertEqual(fake_snapmirrors, result)

    def test__get_snapmirror_svm_fail_to_get_snapmirrors(self):
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(dm_session_mock, 'get_snapmirrors_svm',
                         mock.Mock(
                             side_effect=netapp_api.NaApiError(code=0)))

        self.assertRaises(exception.NetAppException,
                          self.library._get_snapmirror_svm,
                          self.fake_src_share_server,
                          self.fake_dest_share_server)

        dm_session_mock.get_snapmirrors_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    def test_share_server_migration_continue_no_snapmirror(self):
        self.mock_object(self.library, '_get_snapmirror_svm',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.NetAppException,
                          self.library.share_server_migration_continue,
                          None,
                          self.fake_src_share_server,
                          self.fake_dest_share_server,
                          [], [])

        self.library._get_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    @ddt.data({'mirror_state': 'snapmirrored', 'status': 'idle'},
              {'mirror_state': 'uninitialized', 'status': 'transferring'},
              {'mirror_state': 'snapmirrored', 'status': 'quiescing'},)
    @ddt.unpack
    def test_share_server_migration_continue(self, mirror_state, status):
        fake_snapmirror = {
            'mirror-state': mirror_state,
            'relationship-status': status,
        }
        self.mock_object(self.library, '_get_snapmirror_svm',
                         mock.Mock(return_value=[fake_snapmirror]))
        expected = mirror_state == 'snapmirrored' and status == 'idle'

        result = self.library.share_server_migration_continue(
            None,
            self.fake_src_share_server,
            self.fake_dest_share_server,
            [], []
        )

        self.assertEqual(expected, result)
        self.library._get_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    def test_share_server_migration_complete(self):
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=[
                             (self.fake_src_vserver, self.mock_src_client),
                             (self.fake_dest_vserver, self.mock_dest_client)]))
        fake_ipspace = 'fake_ipspace'
        self.mock_object(self.mock_dest_client, 'get_vserver_ipspace',
                         mock.Mock(return_value=fake_ipspace))
        fake_share_name = self.library._get_backend_share_name(
            fake.SHARE_INSTANCE['id'])
        self.mock_object(self.library, '_setup_network_for_vserver')
        fake_volume = copy.deepcopy(fake.CLIENT_GET_VOLUME_RESPONSE)
        self.mock_object(self.mock_dest_client, 'get_volume',
                         mock.Mock(return_value=fake_volume))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value=fake.NFS_EXPORTS))
        self.mock_object(self.library, '_delete_share')
        mock_update_share_attrs = self.mock_object(
            self.library, '_update_share_attributes_after_server_migration')

        result = self.library.share_server_migration_complete(
            None,
            self.fake_src_share_server,
            self.fake_dest_share_server,
            [fake.SHARE_INSTANCE], [],
            fake.NETWORK_INFO
        )

        expected_share_updates = {
            fake.SHARE_INSTANCE['id']: {
                'export_locations': fake.NFS_EXPORTS,
                'pool_name': fake_volume['aggregate']
            }
        }
        expected_result = {
            'share_updates': expected_share_updates,
        }

        self.assertEqual(expected_result, result)
        dm_session_mock.update_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        self.library._get_vserver.assert_has_calls([
            mock.call(share_server=self.fake_src_share_server,
                      backend_name=self.fake_src_backend_name),
            mock.call(share_server=self.fake_dest_share_server,
                      backend_name=self.fake_dest_backend_name)])
        quiesce_break_mock = dm_session_mock.quiesce_and_break_snapmirror_svm
        quiesce_break_mock.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        dm_session_mock.wait_for_vserver_state.assert_called_once_with(
            self.fake_dest_vserver, self.mock_dest_client, subtype='default',
            state='running', operational_state='stopped',
            timeout=(self.library.configuration.
                     netapp_server_migration_state_change_timeout)
        )
        self.mock_src_client.stop_vserver.assert_called_once_with(
            self.fake_src_vserver
        )
        self.mock_dest_client.get_vserver_ipspace.assert_called_once_with(
            self.fake_dest_vserver
        )
        self.library._setup_network_for_vserver.assert_called_once_with(
            self.fake_dest_vserver, self.mock_dest_client, fake.NETWORK_INFO,
            fake_ipspace, enable_nfs=False, security_services=None
        )
        self.mock_dest_client.start_vserver.assert_called_once_with(
            self.fake_dest_vserver
        )
        dm_session_mock.delete_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        self.mock_dest_client.get_volume.assert_called_once_with(
            fake_share_name)
        mock_update_share_attrs.assert_called_once_with(
            fake.SHARE_INSTANCE, self.mock_src_client,
            fake_volume['aggregate'], self.mock_dest_client)
        self.library._delete_share.assert_called_once_with(
            fake.SHARE_INSTANCE, self.mock_src_client, remove_export=True)

    def test_share_server_migration_complete_failure_breaking(self):
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=[
                             (self.fake_src_vserver, self.mock_src_client),
                             (self.fake_dest_vserver, self.mock_dest_client)]))
        self.mock_object(dm_session_mock, 'quiesce_and_break_snapmirror_svm',
                         mock.Mock(side_effect=exception.NetAppException))
        self.mock_object(self.library, '_delete_share')

        self.assertRaises(exception.NetAppException,
                          self.library.share_server_migration_complete,
                          None,
                          self.fake_src_share_server,
                          self.fake_dest_share_server,
                          [fake.SHARE_INSTANCE], [],
                          fake.NETWORK_INFO)

        dm_session_mock.update_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        self.library._get_vserver.assert_has_calls([
            mock.call(share_server=self.fake_src_share_server,
                      backend_name=self.fake_src_backend_name),
            mock.call(share_server=self.fake_dest_share_server,
                      backend_name=self.fake_dest_backend_name)])
        quiesce_break_mock = dm_session_mock.quiesce_and_break_snapmirror_svm
        quiesce_break_mock.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        self.mock_src_client.start_vserver.assert_called_once_with(
            self.fake_src_vserver
        )
        dm_session_mock.cancel_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        self.library._delete_share.assert_called_once_with(
            fake.SHARE_INSTANCE, self.mock_dest_client, remove_export=False)

    def test_share_server_migration_complete_failure_get_new_volume(self):
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=[
                             (self.fake_src_vserver, self.mock_src_client),
                             (self.fake_dest_vserver, self.mock_dest_client)]))
        fake_ipspace = 'fake_ipspace'
        self.mock_object(self.mock_dest_client, 'get_vserver_ipspace',
                         mock.Mock(return_value=fake_ipspace))
        fake_share_name = self.library._get_backend_share_name(
            fake.SHARE_INSTANCE['id'])
        self.mock_object(self.library, '_setup_network_for_vserver')
        self.mock_object(self.mock_dest_client, 'get_volume',
                         mock.Mock(side_effect=exception.NetAppException))

        self.assertRaises(exception.NetAppException,
                          self.library.share_server_migration_complete,
                          None,
                          self.fake_src_share_server,
                          self.fake_dest_share_server,
                          [fake.SHARE_INSTANCE], [],
                          fake.NETWORK_INFO)

        dm_session_mock.update_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        self.library._get_vserver.assert_has_calls([
            mock.call(share_server=self.fake_src_share_server,
                      backend_name=self.fake_src_backend_name),
            mock.call(share_server=self.fake_dest_share_server,
                      backend_name=self.fake_dest_backend_name)])
        quiesce_break_mock = dm_session_mock.quiesce_and_break_snapmirror_svm
        quiesce_break_mock.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        dm_session_mock.wait_for_vserver_state.assert_called_once_with(
            self.fake_dest_vserver, self.mock_dest_client, subtype='default',
            state='running', operational_state='stopped',
            timeout=(self.library.configuration.
                     netapp_server_migration_state_change_timeout)
        )
        self.mock_src_client.stop_vserver.assert_called_once_with(
            self.fake_src_vserver
        )
        self.mock_dest_client.get_vserver_ipspace.assert_called_once_with(
            self.fake_dest_vserver
        )
        self.library._setup_network_for_vserver.assert_called_once_with(
            self.fake_dest_vserver, self.mock_dest_client, fake.NETWORK_INFO,
            fake_ipspace, enable_nfs=False, security_services=None
        )
        self.mock_dest_client.start_vserver.assert_called_once_with(
            self.fake_dest_vserver
        )
        dm_session_mock.delete_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        self.mock_dest_client.get_volume.assert_called_once_with(
            fake_share_name)

    @ddt.data([], ['fake_snapmirror'])
    def test_share_server_migration_cancel(self, snapmirrors):
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(self.fake_dest_vserver,
                                                 self.mock_dest_client)))
        self.mock_object(self.library, '_get_snapmirror_svm',
                         mock.Mock(return_value=snapmirrors))
        self.mock_object(self.library, '_delete_share')

        self.library.share_server_migration_cancel(
            None,
            self.fake_src_share_server,
            self.fake_dest_share_server,
            [fake.SHARE_INSTANCE], []
        )

        self.library._get_vserver.assert_called_once_with(
            share_server=self.fake_dest_share_server,
            backend_name=self.fake_dest_backend_name)
        self.library._get_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        if snapmirrors:
            dm_session_mock.cancel_snapmirror_svm.assert_called_once_with(
                self.fake_src_share_server, self.fake_dest_share_server
            )
        self.library._delete_share.assert_called_once_with(
            fake.SHARE_INSTANCE, self.mock_dest_client, remove_export=False)

    def test_share_server_migration_cancel_snapmirror_failure(self):
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(self.fake_dest_vserver,
                                                 self.mock_dest_client)))
        self.mock_object(self.library, '_get_snapmirror_svm',
                         mock.Mock(return_value=['fake_snapmirror']))
        self.mock_object(dm_session_mock, 'cancel_snapmirror_svm',
                         mock.Mock(side_effect=exception.NetAppException))

        self.assertRaises(exception.NetAppException,
                          self.library.share_server_migration_cancel,
                          None,
                          self.fake_src_share_server,
                          self.fake_dest_share_server,
                          [fake.SHARE_INSTANCE], [])

        self.library._get_vserver.assert_called_once_with(
            share_server=self.fake_dest_share_server,
            backend_name=self.fake_dest_backend_name)
        self.library._get_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        dm_session_mock.cancel_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    def test_share_server_migration_get_progress(self):
        expected_result = {'total_progress': 0}

        result = self.library.share_server_migration_get_progress(
            None, None, None, None, None
        )

        self.assertEqual(expected_result, result)

    @ddt.data({'subtype': 'default',
               'share_group': None,
               'compatible': True},
              {'subtype': 'default',
               'share_group': {'share_server_id': fake.SHARE_SERVER['id']},
               'compatible': True},
              {'subtype': 'dp_destination',
               'share_group': None,
               'compatible': False},
              {'subtype': 'default',
               'share_group': {'share_server_id': 'another_fake_id'},
               'compatible': False})
    @ddt.unpack
    def test_choose_share_server_compatible_with_share_vserver_info(
            self, subtype, share_group, compatible):
        self.library.is_nfs_config_supported = False
        mock_client = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock_client)))
        fake_vserver_info = {
            'operational_state': 'running',
            'state': 'running',
            'subtype': subtype
        }
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake_vserver_info))

        result = self.library.choose_share_server_compatible_with_share(
            None, [fake.SHARE_SERVER], fake.SHARE_INSTANCE,
            None, share_group
        )
        expected_result = fake.SHARE_SERVER if compatible else None
        self.assertEqual(expected_result, result)
        if (share_group and
                share_group['share_server_id'] != fake.SHARE_SERVER['id']):
            mock_client.get_vserver_info.assert_not_called()
            self.library._get_vserver.assert_not_called()
        else:
            mock_client.get_vserver_info.assert_called_once_with(
                fake.VSERVER1,
            )
            self.library._get_vserver.assert_called_once_with(
                fake.SHARE_SERVER, backend_name=fake.BACKEND_NAME
            )

    @ddt.data({'subtype': 'default', 'compatible': True},
              {'subtype': 'dp_destination', 'compatible': False})
    @ddt.unpack
    def test_choose_share_server_compatible_with_share_group_vserver_info(
            self, subtype, compatible):
        self.library.is_nfs_config_supported = False
        mock_client = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock_client)))
        fake_vserver_info = {
            'operational_state': 'running',
            'state': 'running',
            'subtype': subtype
        }
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake_vserver_info))

        result = self.library.choose_share_server_compatible_with_share_group(
            None, [fake.SHARE_SERVER], None
        )
        expected_result = fake.SHARE_SERVER if compatible else None
        self.assertEqual(expected_result, result)
        self.library._get_vserver.assert_called_once_with(
            fake.SHARE_SERVER, backend_name=fake.BACKEND_NAME
        )
        mock_client.get_vserver_info.assert_called_once_with(
            fake.VSERVER1,
        )

    def test__create_port_and_broadcast_domain(self):
        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library,
                         '_get_node_data_port',
                         mock.Mock(return_value='fake_port'))

        self.library._create_port_and_broadcast_domain(fake.IPSPACE,
                                                       fake.NETWORK_INFO)
        node_network_info = zip(fake.CLUSTER_NODES,
                                fake.NETWORK_INFO['network_allocations'])
        get_node_port_calls = []
        create_port_calls = []
        for node, alloc in node_network_info:
            get_node_port_calls.append(mock.call(node))
            create_port_calls.append(mock.call(
                node, 'fake_port', alloc['segmentation_id'], alloc['mtu'],
                fake.IPSPACE
            ))

        self.library._get_node_data_port.assert_has_calls(get_node_port_calls)
        self.library._client.create_port_and_broadcast_domain.assert_has_calls(
            create_port_calls)

    def test___update_share_attributes_after_server_migration(self):
        fake_aggregate = 'fake_aggr_0'
        mock_get_extra_spec = self.mock_object(
            share_types, "get_extra_specs_from_share",
            mock.Mock(return_value=fake.EXTRA_SPEC))
        mock__get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options',
            mock.Mock(return_value=copy.deepcopy(fake.PROVISIONING_OPTIONS)))
        fake_share_name = self.library._get_backend_share_name(
            fake.SHARE_INSTANCE['id'])
        mock_get_vol_autosize_attrs = self.mock_object(
            self.mock_src_client, 'get_volume_autosize_attributes',
            mock.Mock(return_value=fake.VOLUME_AUTOSIZE_ATTRS)
        )
        fake_provisioning_opts = copy.copy(fake.PROVISIONING_OPTIONS)
        fake_autosize_attrs = copy.copy(fake.VOLUME_AUTOSIZE_ATTRS)
        for key in ('minimum-size', 'maximum-size'):
            fake_autosize_attrs[key] = int(fake_autosize_attrs[key]) * units.Ki
        fake_provisioning_opts['autosize_attributes'] = fake_autosize_attrs
        mock_modify_volume = self.mock_object(self.mock_dest_client,
                                              'modify_volume')
        fake_provisioning_opts.pop('snapshot_policy', None)

        self.library._update_share_attributes_after_server_migration(
            fake.SHARE_INSTANCE, self.mock_src_client, fake_aggregate,
            self.mock_dest_client)

        mock_get_extra_spec.assert_called_once_with(fake.SHARE_INSTANCE)
        mock__get_provisioning_opts.assert_called_once_with(fake.EXTRA_SPEC)
        mock_get_vol_autosize_attrs.assert_called_once_with(fake_share_name)
        mock_modify_volume.assert_called_once_with(
            fake_aggregate, fake_share_name, **fake_provisioning_opts)

    def test_validate_provisioning_options_for_share(self):
        mock_create_from_snap = self.mock_object(
            lib_base.NetAppCmodeFileStorageLibrary,
            'validate_provisioning_options_for_share')

        self.library.validate_provisioning_options_for_share(
            fake.PROVISIONING_OPTIONS, extra_specs=fake.EXTRA_SPEC,
            qos_specs=fake.QOS_NORMALIZED_SPEC)

        mock_create_from_snap.assert_called_once_with(
            fake.PROVISIONING_OPTIONS, extra_specs=fake.EXTRA_SPEC,
            qos_specs=fake.QOS_NORMALIZED_SPEC)

    def test_validate_provisioning_options_for_share_aqos_not_supported(self):
        self.assertRaises(
            exception.NetAppException,
            self.library.validate_provisioning_options_for_share,
            fake.PROVISIONING_OPTS_WITH_ADAPT_QOS, qos_specs=None)
