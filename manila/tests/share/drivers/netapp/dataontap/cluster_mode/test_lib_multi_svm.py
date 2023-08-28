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
        mock_list_non_root_aggregates = self.mock_object(
            self.client, 'list_non_root_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        mock_init_flexgroup = self.mock_object(self.library,
                                               '_initialize_flexgroup_pools')
        self.mock_object(self.library,
                         'is_flexvol_pool_configured',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      'check_for_setup_error')

        self.library.check_for_setup_error()

        mock_list_non_root_aggregates.assert_called_once_with()
        mock_init_flexgroup.assert_called_once_with(set(fake.AGGREGATES))
        self.assertTrue(self.library.is_flexvol_pool_configured.called)
        self.assertTrue(self.library._find_matching_aggregates.called)
        mock_super.assert_called_once_with()

    def test_check_for_setup_error_cluster_creds_with_vserver(self):
        self.library._have_cluster_creds = True
        self.library.configuration.netapp_vserver = fake.VSERVER1
        mock_list_non_root_aggregates = self.mock_object(
            self.client, 'list_non_root_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        mock_init_flexgroup = self.mock_object(self.library,
                                               '_initialize_flexgroup_pools')
        self.mock_object(self.library,
                         'is_flexvol_pool_configured',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_super = self.mock_object(lib_base.NetAppCmodeFileStorageLibrary,
                                      'check_for_setup_error')

        self.library.check_for_setup_error()

        mock_super.assert_called_once_with()
        mock_list_non_root_aggregates.assert_called_once_with()
        mock_init_flexgroup.assert_called_once_with(set(fake.AGGREGATES))
        self.assertTrue(self.library.is_flexvol_pool_configured.called)
        self.assertTrue(self.library._find_matching_aggregates.called)
        self.assertTrue(lib_multi_svm.LOG.warning.called)

    def test_check_for_setup_error_no_aggregates_no_flexvol_pool(self):
        self.library._have_cluster_creds = True
        mock_list_non_root_aggregates = self.mock_object(
            self.client, 'list_non_root_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        mock_init_flexgroup = self.mock_object(self.library,
                                               '_initialize_flexgroup_pools')
        self.mock_object(self.library,
                         'is_flexvol_pool_configured',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=[]))

        self.library.check_for_setup_error()

        mock_list_non_root_aggregates.assert_called_once_with()
        mock_init_flexgroup.assert_called_once_with(set(fake.AGGREGATES))
        self.assertTrue(self.library.is_flexvol_pool_configured.called)
        self.assertTrue(self.library._find_matching_aggregates.called)

    def test_check_for_setup_error_vserver_creds(self):
        self.library._have_cluster_creds = False

        self.assertRaises(exception.InvalidInput,
                          self.library.check_for_setup_error)

    def test_check_for_setup_error_no_aggregates(self):
        self.library._have_cluster_creds = True
        mock_list_non_root_aggregates = self.mock_object(
            self.client, 'list_non_root_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        mock_init_flexgroup = self.mock_object(self.library,
                                               '_initialize_flexgroup_pools')
        self.mock_object(self.library,
                         'is_flexvol_pool_configured',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.NetAppException,
                          self.library.check_for_setup_error)

        mock_list_non_root_aggregates.assert_called_once_with()
        mock_init_flexgroup.assert_called_once_with(set(fake.AGGREGATES))
        self.assertTrue(self.library.is_flexvol_pool_configured.called)
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
        self.library._flexgroup_pools = {'fg': ['aggr1', 'aggr2']}

        result = self.library._get_ems_pool_info()

        expected = {
            'pools': {
                'vserver': None,
                'aggregates': ['aggr1', 'aggr2'],
                'flexgroup_aggregates': {'fg': ['aggr1', 'aggr2']},
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

        mock_is_flexvol_pool_configured = self.mock_object(
            self.library, 'is_flexvol_pool_configured',
            mock.Mock(return_value=True))
        mock_list_non_root_aggregates = self.mock_object(
            self.client, 'list_non_root_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        self.library.configuration.netapp_aggregate_name_search_pattern = (
            '.*_aggr_1')

        result = self.library._find_matching_aggregates()

        self.assertListEqual([fake.AGGREGATES[0]], result)
        mock_is_flexvol_pool_configured.assert_called_once_with()
        mock_list_non_root_aggregates.assert_called_once_with()
        mock_list_non_root_aggregates.assert_called_once_with()

    def test_find_matching_aggregates_no_flexvol_pool(self):

        self.mock_object(self.library,
                         'is_flexvol_pool_configured',
                         mock.Mock(return_value=False))

        result = self.library._find_matching_aggregates()

        self.assertListEqual([], result)

    def test__set_network_with_metadata(self):
        net_info_1 = copy.deepcopy(fake.NETWORK_INFO)
        net_info_2 = copy.deepcopy(fake.NETWORK_INFO)
        net_info_2['subnet_metadata'] = {'fake_key': 'fake_value'}
        net_info_3 = copy.deepcopy(fake.NETWORK_INFO)
        metadata_vlan = 1
        net_info_3['subnet_metadata'] = {
            'set_vlan': metadata_vlan,
            'set_mtu': '1'
        }
        net_info_4 = copy.deepcopy(fake.NETWORK_INFO)
        metadata_vlan = 1
        net_info_4['subnet_metadata'] = {
            'set_vlan': metadata_vlan
        }

        net_list = [net_info_1, net_info_2, net_info_3, net_info_4]
        self.library._set_network_with_metadata(net_list)

        net_info = copy.deepcopy(fake.NETWORK_INFO)
        self.assertEqual(net_info, net_list[0])
        net_info['subnet_metadata'] = {'fake_key': 'fake_value'}
        self.assertEqual(net_info, net_list[1])
        self.assertEqual(metadata_vlan, net_list[2]['segmentation_id'])
        for allocation in net_list[2]['network_allocations']:
            self.assertEqual(metadata_vlan, allocation['segmentation_id'])
            self.assertEqual(1, allocation['mtu'])
        self.assertEqual(metadata_vlan, net_list[3]['segmentation_id'])
        for allocation in net_list[3]['network_allocations']:
            self.assertEqual(metadata_vlan, allocation['segmentation_id'])
            self.assertEqual(fake.MTU, allocation['mtu'])

    @ddt.data({'set_vlan': '0', 'set_mtu': '1500'},
              {'set_vlan': '1000', 'set_mtu': '1bla'})
    def test__set_network_with_metadata_exception(self, metadata):
        net_info = copy.deepcopy(fake.NETWORK_INFO)
        net_info['subnet_metadata'] = metadata

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            self.library._set_network_with_metadata,
            [net_info])

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
        mock_validate_share_network_subnets = self.mock_object(
            self.library,
            '_validate_share_network_subnets')
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
        mock_set_with_meta = self.mock_object(
            self.library, '_set_network_with_metadata')

        result = self.library.setup_server(fake.NETWORK_INFO_LIST,
                                           fake.SERVER_METADATA)

        ports = {}
        for network_allocation in fake.NETWORK_INFO['network_allocations']:
            ports[network_allocation['id']] = network_allocation['ip_address']

        mock_set_with_meta.assert_called_once_with(fake.NETWORK_INFO_LIST)
        self.assertTrue(mock_validate_network_type.called)
        self.assertTrue(mock_validate_share_network_subnets.called)
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

        mock_validate_share_network_subnets = self.mock_object(
            self.library,
            '_validate_share_network_subnets')
        self.mock_object(self.library, '_set_network_with_metadata')

        self.assertRaises(
            exception.ManilaException,
            self.library.setup_server,
            fake.NETWORK_INFO_LIST,
            fake.SERVER_METADATA)

        ports = {}
        for network_allocation in fake.NETWORK_INFO['network_allocations']:
            ports[network_allocation['id']] = network_allocation['ip_address']

        self.assertTrue(mock_validate_network_type.called)
        self.assertTrue(mock_validate_share_network_subnets.called)
        self.assertTrue(mock_get_vserver_name.called)
        self.assertTrue(mock_create_vserver.called)

        self.assertDictEqual(
            {'server_details': {
                'vserver_name': fake.VSERVER1,
                'ports': jsonutils.dumps(ports),
            }},
            fake_exception.detail_data)

    def test_setup_server_invalid_subnet(self):
        invalid_subnet_exception = exception.NetworkBadConfigurationException(
            reason='This is a fake message')
        self.mock_object(self.library, '_get_vserver_name',
                         mock.Mock(return_value=fake.VSERVER1))
        self.mock_object(self.library, '_validate_network_type')
        self.mock_object(self.library, '_validate_share_network_subnets',
                         mock.Mock(side_effect=invalid_subnet_exception))
        self.mock_object(self.library, '_set_network_with_metadata')

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            self.library.setup_server,
            fake.NETWORK_INFO_LIST)

        self.library._validate_share_network_subnets.assert_called_once_with(
            fake.NETWORK_INFO_LIST)

    def test_validate_share_network_subnets(self):
        fake_vlan = fake.NETWORK_INFO['segmentation_id']
        network_info_different_seg_id = copy.deepcopy(fake.NETWORK_INFO)
        network_info_different_seg_id['segmentation_id'] = fake_vlan
        allocations = network_info_different_seg_id['network_allocations']
        allocations[0]['segmentation_id'] = fake_vlan
        fake.NETWORK_INFO_LIST.append(network_info_different_seg_id)

        result = self.library._validate_share_network_subnets(
            fake.NETWORK_INFO_LIST)

        self.assertIsNone(result)

    def test_validate_share_network_subnets_invalid_vlan_config(self):
        network_info_different_seg_id = copy.deepcopy(fake.NETWORK_INFO)
        network_info_different_seg_id['segmentation_id'] = 4004
        allocations = network_info_different_seg_id['network_allocations']
        allocations[0]['segmentation_id'] = 4004
        fake.NETWORK_INFO_LIST.append(network_info_different_seg_id)

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            self.library._validate_share_network_subnets,
            fake.NETWORK_INFO_LIST)

    @ddt.data(
        {'network_info': [{'network_type': 'vlan', 'segmentation_id': 1000}]},
        {'network_info': [{'network_type': None, 'segmentation_id': None}]},
        {'network_info': [{'network_type': 'flat', 'segmentation_id': None}]})
    @ddt.unpack
    def test_validate_network_type_with_valid_network_types(self,
                                                            network_info):
        result = self.library._validate_network_type(network_info)
        self.assertIsNone(result)

    @ddt.data(
        {'network_info': [{'network_type': 'vxlan', 'segmentation_id': 1000}]},
        {'network_info': [{'network_type': 'gre', 'segmentation_id': 100}]})
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
        fake_lif_home_ports = {fake.CLUSTER_NODES[0]: 'fake_port',
                               fake.CLUSTER_NODES[1]: 'another_fake_port'}

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
                         '_get_flexgroup_aggr_set',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library,
                         '_create_ipspace',
                         mock.Mock(return_value=fake.IPSPACE))
        self.mock_object(self.library,
                         '_create_vserver_lifs')
        self.mock_object(self.library,
                         '_create_vserver_routes')
        self.mock_object(self.library,
                         '_create_vserver_admin_lif')
        self.mock_object(self.library._client,
                         'create_port_and_broadcast_domain',
                         mock.Mock(side_effect=['fake_port',
                                                'another_fake_port']))
        get_ipspace_name_for_vlan_port = self.mock_object(
            self.library._client,
            'get_ipspace_name_for_vlan_port',
            mock.Mock(return_value=existing_ipspace))

        self.library._create_vserver(vserver_name, fake.NETWORK_INFO_LIST,
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
            set(fake.AGGREGATES), fake.IPSPACE,
            fake.SECURITY_CERT_DEFAULT_EXPIRE_DAYS)
        self.library._get_api_client.assert_called_once_with(
            vserver=vserver_name)
        self.library._create_vserver_lifs.assert_called_once_with(
            vserver_name, vserver_client, fake.NETWORK_INFO, fake.IPSPACE,
            lif_home_ports=fake_lif_home_ports)
        self.library._create_vserver_routes.assert_called_once_with(
            vserver_client, fake.NETWORK_INFO)
        self.library._create_vserver_admin_lif.assert_called_once_with(
            vserver_name, vserver_client, fake.NETWORK_INFO, fake.IPSPACE,
            lif_home_ports=fake_lif_home_ports)
        vserver_client.enable_nfs.assert_called_once_with(
            versions, nfs_config=nfs_config)
        self.library._client.setup_security_services.assert_called_once_with(
            fake.NETWORK_INFO['security_services'], vserver_client,
            vserver_name)
        self.library._get_flexgroup_aggr_set.assert_called_once_with()

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
                         '_get_flexgroup_aggr_set',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library,
                         '_create_ipspace',
                         mock.Mock(return_value=fake.IPSPACE))

        get_ipspace_name_for_vlan_port = self.mock_object(
            self.library._client,
            'get_ipspace_name_for_vlan_port',
            mock.Mock(return_value=existing_ipspace))
        self.mock_object(self.library, '_create_port_and_broadcast_domain')

        self.library._create_vserver(vserver_name, fake.NETWORK_INFO_LIST,
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
        self.library._get_flexgroup_aggr_set.assert_not_called()

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
        self.mock_object(self.library,
                         '_get_flexgroup_aggr_set',
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
                          fake.NETWORK_INFO_LIST,
                          fake.NFS_CONFIG_TCP_UDP_MAX)

        self.library._get_api_client.assert_called_with(vserver=vserver_name)
        self.assertTrue(self.library._client.create_vserver.called)
        self.library._setup_network_for_vserver.assert_called_with(
            vserver_name,
            vserver_client,
            fake.NETWORK_INFO_LIST,
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
                      fake.NETWORK_INFO['network_allocations'][0],
                      lif_home_port=None),
            mock.call('fake_vserver_client', fake.VSERVER1, fake.IPSPACE,
                      fake.CLUSTER_NODES[1], 'fake_lif2',
                      fake.NETWORK_INFO['network_allocations'][1],
                      lif_home_port=None)])

    def test_create_vserver_lifs_pre_configured_home_ports(self):

        self.mock_object(self.library._client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library,
                         '_get_lif_name',
                         mock.Mock(side_effect=['fake_lif1', 'fake_lif2']))
        self.mock_object(self.library, '_create_lif')

        lif_home_ports = {
            fake.CLUSTER_NODES[0]: 'fake_port1',
            fake.CLUSTER_NODES[1]: 'fake_port2'
        }

        self.library._create_vserver_lifs(fake.VSERVER1,
                                          'fake_vserver_client',
                                          fake.NETWORK_INFO,
                                          fake.IPSPACE,
                                          lif_home_ports=lif_home_ports)

        self.library._create_lif.assert_has_calls([
            mock.call('fake_vserver_client', fake.VSERVER1, fake.IPSPACE,
                      fake.CLUSTER_NODES[0], 'fake_lif1',
                      fake.NETWORK_INFO['network_allocations'][0],
                      lif_home_port=lif_home_ports[fake.CLUSTER_NODES[0]]),
            mock.call('fake_vserver_client', fake.VSERVER1, fake.IPSPACE,
                      fake.CLUSTER_NODES[1], 'fake_lif2',
                      fake.NETWORK_INFO['network_allocations'][1],
                      lif_home_port=lif_home_ports[fake.CLUSTER_NODES[1]])])

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
                      fake.NETWORK_INFO['admin_network_allocations'][0],
                      lif_home_port=None)])

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

        self.mock_object(self.library, '_get_node_data_port',
                         mock.Mock(return_value='fake_port'))

        vserver_client.network_interface_exists = mock.Mock(
            return_value=False)

        self.library._client.create_port_and_broadcast_domain = (
            mock.Mock(return_value='fake_port'))

        self.library._create_lif(vserver_client,
                                 'fake_vserver',
                                 'fake_ipspace',
                                 'fake_node',
                                 'fake_lif',
                                 network_allocations,
                                 lif_home_port=None)

        self.library._get_node_data_port.assert_called_once_with(
            'fake_node')

        (vserver_client.network_interface_exists
         .assert_called_once_with('fake_vserver', 'fake_node', 'fake_port',
                                  '10.10.10.10', '255.255.255.0', '1000',
                                  home_port=None))

        (self.library._client.create_port_and_broadcast_domain
         .assert_called_once_with('fake_node', 'fake_port', '1000',
                                  expected_mtu, 'fake_ipspace'))

        (self.library._client.create_network_interface
         .assert_called_once_with('10.10.10.10', '255.255.255.0',
                                  'fake_node', 'fake_port',
                                  'fake_vserver', 'fake_lif'))

    def test_create_lif_existent_home_port(self):
        """Tests case where a existent port is passed to the function"""

        network_allocations = copy.deepcopy(
            fake.NETWORK_INFO['network_allocations'][0])

        vserver_client = mock.Mock()
        mock_get_node_data_port = self.mock_object(
            self.library, '_get_node_data_port')

        vserver_client.network_interface_exists = mock.Mock(
            return_value=False)

        mock_create_port_and_broadcast_domain = (
            self.library._client.create_port_and_broadcast_domain)

        self.library._create_lif(vserver_client,
                                 'fake_vserver',
                                 'fake_ipspace',
                                 'fake_node',
                                 'fake_lif',
                                 network_allocations,
                                 lif_home_port='fake_port_from_param')

        (vserver_client.network_interface_exists
         .assert_called_once_with('fake_vserver', 'fake_node',
                                  'fake_port_from_param',
                                  '10.10.10.10', '255.255.255.0', '1000',
                                  home_port='fake_port_from_param'))

        mock_get_node_data_port.assert_not_called()
        mock_create_port_and_broadcast_domain.assert_not_called()

        (self.library._client.create_network_interface
         .assert_called_once_with('10.10.10.10', '255.255.255.0',
                                  'fake_node', 'fake_port_from_param',
                                  'fake_vserver', 'fake_lif'))

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
                                 fake.NETWORK_INFO['network_allocations'][0],
                                 lif_home_port=None)

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

        self.assertDictEqual(lib_base_model_update, model_update)
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

    def test_create_share_from_snapshot(self):
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

    def test_create_share_from_snapshot_group(self):
        share = copy.deepcopy(fake.SHARE)
        share['source_share_group_snapshot_member_id'] = (
            fake.CG_SNAPSHOT_MEMBER_ID1)
        fake_parent_share = copy.deepcopy(fake.SHARE)
        fake_parent_share['id'] = fake.SHARE_ID2
        fake_parent_share['host'] = fake.MANILA_HOST_NAME_2
        mock_create_from_snap = self.mock_object(
            lib_base.NetAppCmodeFileStorageLibrary,
            'create_share_from_snapshot')
        mock_data_session = self.mock_object(data_motion, 'DataMotionSession')

        self.library.create_share_from_snapshot(
            None, share, fake.SNAPSHOT, share_server=fake.SHARE_SERVER,
            parent_share=fake_parent_share)

        mock_create_from_snap.assert_called_once_with(
            None, share, fake.SNAPSHOT, share_server=fake.SHARE_SERVER,
            parent_share=fake_parent_share
        )
        mock_data_session.assert_not_called()

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
            mock.Mock(return_value=src_vserver))
        mock_get_vserver_from_share_server = self.mock_object(
            mock_dm_session, 'get_vserver_from_share_server',
            mock.Mock(return_value=dest_vserver))
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
        mock_get_vserver.assert_called_once_with(fake_parent_share)
        mock_get_vserver_from_share_server.assert_called_once_with(
            fake_share_server)
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
        self.mock_object(mock_client, 'list_vserver_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))

        server = self.library.choose_share_server_compatible_with_share(
            None, fake.SHARE_SERVERS, fake.SHARE_2, None, share_group)

        mock_get_extra_spec.assert_called_once_with(fake.SHARE_2)
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
        self.mock_object(mock_client, 'list_vserver_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))

        server = self.library.choose_share_server_compatible_with_share(
            None, fake.SHARE_SERVERS, fake.SHARE_2, None, share_group)

        self.assertEqual(expected_server, server)
        if nfs_config_support:
            mock_get_extra_spec.assert_called_once_with(fake.SHARE_2)
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
        self.mock_object(mock_client, 'list_vserver_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))

        server = self.library.choose_share_server_compatible_with_share(
            None, fake.SHARE_SERVERS, fake.SHARE_2)

        self.assertEqual(expected_server, server)
        if nfs_config_support:
            mock_get_extra_spec.assert_called_once_with(fake.SHARE_2)
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
        self.mock_object(mock_client, 'list_vserver_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))

        server = self.library.choose_share_server_compatible_with_share(
            None, share_servers, fake.SHARE_2)

        self.assertEqual(expected_server, server)
        if nfs_config_support:
            mock_get_extra_spec.assert_called_once_with(fake.SHARE_2)
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
        mock_client = mock.Mock()
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

    def _init_mocks_for_svm_dr_check_compatibility(
            self, src_svm_dr_supported=True, dest_svm_dr_supported=True,
            check_capacity_result=True, flexgroup_support=False,
            is_flexgroup_destination_host=False):
        self.mock_object(self.mock_src_client, 'is_svm_dr_supported',
                         mock.Mock(return_value=src_svm_dr_supported))
        self.mock_object(self.mock_dest_client, 'is_svm_dr_supported',
                         mock.Mock(return_value=dest_svm_dr_supported))
        self.mock_object(self.library, '_check_capacity_compatibility',
                         mock.Mock(return_value=check_capacity_result))
        self.mock_object(self.mock_src_client, 'is_flexgroup_supported',
                         mock.Mock(return_value=flexgroup_support))
        self.mock_object(data_motion, 'DataMotionSession')
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=is_flexgroup_destination_host))

    def _configure_mocks_share_server_migration_check_compatibility(
            self, have_cluster_creds=True,
            src_cluster_name=fake.CLUSTER_NAME,
            dest_cluster_name=fake.CLUSTER_NAME_2,
            pools=fake.POOLS, is_svm_dr=True, failure_scenario=False):
        migration_method = 'svm_dr' if is_svm_dr else 'svm_migrate'

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
        self.mock_object(self.library, '_check_for_migration_support',
                         mock.Mock(return_value=(
                             migration_method, not failure_scenario)))
        self.mock_object(self.library, '_get_pools',
                         mock.Mock(return_value=pools))

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

    @ddt.data(
        {'src_svm_dr_supported': False,
         'dest_svm_dr_supported': False,
         'check_capacity_result': False,
         'is_flexgroup_destination_host': False,
         },
        {'src_svm_dr_supported': True,
         'dest_svm_dr_supported': True,
         'check_capacity_result': False,
         'is_flexgroup_destination_host': False,
         },
        {'src_svm_dr_supported': True,
         'dest_svm_dr_supported': True,
         'check_capacity_result': True,
         'is_flexgroup_destination_host': True,
         },
    )
    @ddt.unpack
    def test__check_compatibility_svm_dr_not_compatible(
            self, src_svm_dr_supported, dest_svm_dr_supported,
            check_capacity_result, is_flexgroup_destination_host):
        server_total_size = (fake.SHARE_REQ_SPEC.get('shares_size', 0) +
                             fake.SHARE_REQ_SPEC.get('snapshots_size', 0))

        self._init_mocks_for_svm_dr_check_compatibility(
            src_svm_dr_supported=src_svm_dr_supported,
            dest_svm_dr_supported=dest_svm_dr_supported,
            check_capacity_result=check_capacity_result,
            flexgroup_support=is_flexgroup_destination_host,
            is_flexgroup_destination_host=is_flexgroup_destination_host)

        method, result = self.library._check_compatibility_using_svm_dr(
            self.mock_src_client, self.mock_dest_client,
            fake.SERVER_MIGRATION_REQUEST_SPEC, fake.POOLS)

        self.assertEqual(method, 'svm_dr')
        self.assertEqual(result, False)
        self.assertTrue(self.mock_src_client.is_svm_dr_supported.called)

        if (src_svm_dr_supported and dest_svm_dr_supported and
                is_flexgroup_destination_host):
            self.assertTrue(self.mock_src_client.is_flexgroup_supported.called)
            self.assertTrue(self.library.is_flexgroup_destination_host.called)

        if (check_capacity_result and not is_flexgroup_destination_host and
                not src_svm_dr_supported):
            self.assertFalse(self.mock_dest_client.is_svm_dr_supported.called)
            self.library._check_capacity_compatibility.assert_called_once_with(
                fake.POOLS, True, server_total_size)

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

    @ddt.data((True, "svm_migrate"), (False, "svm_dr"))
    @ddt.unpack
    def test__check_for_migration_support(
            self, svm_migrate_supported, expected_migration_method):
        mock_dest_is_svm_migrate_supported = self.mock_object(
            self.mock_dest_client, 'is_svm_migrate_supported',
            mock.Mock(return_value=svm_migrate_supported))
        mock_src_is_svm_migrate_supported = self.mock_object(
            self.mock_src_client, 'is_svm_migrate_supported',
            mock.Mock(return_value=svm_migrate_supported))
        mock_find_matching_aggregates = self.mock_object(
            self.library, '_find_matching_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        mock_get_vserver_name = self.mock_object(
            self.library, '_get_vserver_name',
            mock.Mock(return_value=fake.VSERVER1))
        mock_svm_migration_check_svm_mig = self.mock_object(
            self.library, '_check_compatibility_for_svm_migrate',
            mock.Mock(return_value=True))
        mock_svm_migration_check_svm_dr = self.mock_object(
            self.library, '_check_compatibility_using_svm_dr',
            mock.Mock(side_effect=[('svm_dr', True)]))

        migration_method, result = self.library._check_for_migration_support(
            self.mock_src_client, self.mock_dest_client, fake.SHARE_SERVER,
            fake.SHARE_REQ_SPEC, fake.CLUSTER_NAME, fake.POOLS)

        self.assertIs(True, result)
        self.assertEqual(migration_method, expected_migration_method)

        mock_dest_is_svm_migrate_supported.assert_called_once()
        if svm_migrate_supported:
            mock_src_is_svm_migrate_supported.assert_called_once()
            mock_find_matching_aggregates.assert_called_once()
            mock_get_vserver_name.assert_called_once_with(
                fake.SHARE_SERVER['id'])
            mock_svm_migration_check_svm_mig.assert_called_once_with(
                fake.CLUSTER_NAME, fake.VSERVER1, fake.SHARE_SERVER,
                fake.AGGREGATES, self.mock_dest_client)
        else:
            mock_svm_migration_check_svm_dr.assert_called_once_with(
                self.mock_src_client, self.mock_dest_client,
                fake.SHARE_REQ_SPEC, fake.POOLS)

    def test__check_for_migration_support_svm_migrate_exception(self):
        svm_migrate_supported = True
        expected_migration_method = 'svm_migrate'
        mock_dest_is_svm_migrate_supported = self.mock_object(
            self.mock_dest_client, 'is_svm_migrate_supported',
            mock.Mock(return_value=svm_migrate_supported))
        mock_src_is_svm_migrate_supported = self.mock_object(
            self.mock_src_client, 'is_svm_migrate_supported',
            mock.Mock(return_value=svm_migrate_supported))
        mock_find_matching_aggregates = self.mock_object(
            self.library, '_find_matching_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        mock_get_vserver_name = self.mock_object(
            self.library, '_get_vserver_name',
            mock.Mock(return_value=fake.VSERVER1))
        mock_svm_migration_check_svm_mig = self.mock_object(
            self.library, '_check_compatibility_for_svm_migrate',
            mock.Mock(side_effect=exception.NetAppException()))

        migration_method, result = self.library._check_for_migration_support(
            self.mock_src_client, self.mock_dest_client, fake.SHARE_SERVER,
            fake.SHARE_REQ_SPEC, fake.CLUSTER_NAME, fake.POOLS)

        self.assertIs(False, result)
        self.assertEqual(migration_method, expected_migration_method)

        mock_dest_is_svm_migrate_supported.assert_called_once()
        mock_src_is_svm_migrate_supported.assert_called_once()
        mock_find_matching_aggregates.assert_called_once()
        mock_get_vserver_name.assert_called_once_with(
            fake.SHARE_SERVER['id'])
        mock_svm_migration_check_svm_mig.assert_called_once_with(
            fake.CLUSTER_NAME, fake.VSERVER1, fake.SHARE_SERVER,
            fake.AGGREGATES, self.mock_dest_client)

    @ddt.data(
        (mock.Mock, True),
        (exception.NetAppException, False)
    )
    @ddt.unpack
    def test__check_compatibility_for_svm_migrate(self, expected_exception,
                                                  expected_compatibility):
        network_info = {
            'network_allocations':
                self.fake_src_share_server['network_allocations'],
            'neutron_subnet_id':
                self.fake_src_share_server['share_network_subnets'][0].get(
                    'neutron_subnet_id')
        }
        self.mock_object(self.library._client, 'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library, '_get_node_data_port',
                         mock.Mock(return_value=fake.NODE_DATA_PORT))
        self.mock_object(
            self.library._client, 'get_ipspace_name_for_vlan_port',
            mock.Mock(return_value=fake.IPSPACE))
        self.mock_object(self.library, '_create_port_and_broadcast_domain')
        self.mock_object(self.mock_dest_client, 'get_ipspaces',
                         mock.Mock(return_value=[{'uuid': fake.IPSPACE_ID}]))
        self.mock_object(
            self.mock_dest_client, 'svm_migration_start',
            mock.Mock(return_value=c_fake.FAKE_MIGRATION_RESPONSE_WITH_JOB))
        self.mock_object(self.library, '_get_job_uuid',
                         mock.Mock(return_value=c_fake.FAKE_JOB_ID))
        self.mock_object(self.library, '_wait_for_operation_status',
                         mock.Mock(side_effect=expected_exception))

        compatibility = self.library._check_compatibility_for_svm_migrate(
            fake.CLUSTER_NAME, fake.VSERVER1, self.fake_src_share_server,
            fake.AGGREGATES, self.mock_dest_client)

        self.assertIs(expected_compatibility, compatibility)
        self.mock_dest_client.svm_migration_start.assert_called_once_with(
            fake.CLUSTER_NAME, fake.VSERVER1, fake.AGGREGATES, check_only=True,
            dest_ipspace=fake.IPSPACE)
        self.library._get_job_uuid.assert_called_once_with(
            c_fake.FAKE_MIGRATION_RESPONSE_WITH_JOB)
        self.library._client.list_cluster_nodes.assert_called_once()
        self.library._get_node_data_port.assert_called_once_with(
            fake.CLUSTER_NODES[0])
        (self.library._client.get_ipspace_name_for_vlan_port
            .assert_called_once_with(
                fake.CLUSTER_NODES[0], fake.NODE_DATA_PORT,
                self.fake_src_share_server['network_allocations'][0][
                    'segmentation_id']))
        self.library._create_port_and_broadcast_domain.assert_called_once_with(
            fake.IPSPACE, network_info)

    def test__check_compatibility_for_svm_migrate_check_failure(self):
        network_info = {
            'network_allocations':
                self.fake_src_share_server['network_allocations'],
            'neutron_subnet_id':
                self.fake_src_share_server['share_network_subnets'][0].get(
                    'neutron_subnet_id')
        }

        self.mock_object(self.library._client, 'list_cluster_nodes',
                         mock.Mock(return_value=fake.CLUSTER_NODES))
        self.mock_object(self.library, '_get_node_data_port',
                         mock.Mock(return_value=fake.NODE_DATA_PORT))
        self.mock_object(
            self.library._client, 'get_ipspace_name_for_vlan_port',
            mock.Mock(return_value=fake.IPSPACE))
        self.mock_object(self.library, '_create_port_and_broadcast_domain')
        self.mock_object(self.mock_dest_client, 'get_ipspaces',
                         mock.Mock(return_value=[{'uuid': fake.IPSPACE_ID}]))
        self.mock_object(
            self.mock_dest_client, 'svm_migration_start',
            mock.Mock(side_effect=exception.NetAppException()))
        self.mock_object(self.mock_dest_client, 'delete_ipspace')

        self.assertRaises(
            exception.NetAppException,
            self.library._check_compatibility_for_svm_migrate,
            fake.CLUSTER_NAME,
            fake.VSERVER1,
            self.fake_src_share_server,
            fake.AGGREGATES,
            self.mock_dest_client)

        self.library._client.list_cluster_nodes.assert_called_once()
        self.library._get_node_data_port.assert_called_once_with(
            fake.CLUSTER_NODES[0])
        (self.library._client.get_ipspace_name_for_vlan_port
            .assert_called_once_with(
                fake.CLUSTER_NODES[0], fake.NODE_DATA_PORT,
                self.fake_src_share_server['network_allocations'][0][
                    'segmentation_id']))
        self.library._create_port_and_broadcast_domain.assert_called_once_with(
            fake.IPSPACE, network_info)
        self.mock_dest_client.delete_ipspace.assert_called_once_with(
            fake.IPSPACE)

    def test_share_server_migration_check_compatibility_compatible(self):
        compatible = {
            'compatible': True,
            'writable': True,
            'nondisruptive': False,
            'preserve_snapshots': True,
            'migration_cancel': True,
            'migration_get_progress': False,
            'share_network_id': fake.SHARE_NETWORK['id'],
        }
        self._configure_mocks_share_server_migration_check_compatibility(
            is_svm_dr=True)

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

    def test__get_job_uuid(self):
        self.assertEqual(
            self.library._get_job_uuid(
                c_fake.FAKE_MIGRATION_RESPONSE_WITH_JOB),
            c_fake.FAKE_JOB_ID
        )

    def test__wait_for_operation_status(self):
        job_starting_state = copy.copy(c_fake.FAKE_JOB_SUCCESS_STATE)
        job_starting_state['state'] = 'starting'
        returned_jobs = [
            job_starting_state,
            c_fake.FAKE_JOB_SUCCESS_STATE,
        ]

        self.mock_object(self.mock_dest_client, 'get_job',
                         mock.Mock(side_effect=returned_jobs))

        self.library._wait_for_operation_status(
            c_fake.FAKE_JOB_ID, self.mock_dest_client.get_job
        )

        self.assertEqual(
            self.mock_dest_client.get_job.call_count, len(returned_jobs))

    def test__wait_for_operation_status_error(self):
        starting_job = copy.copy(c_fake.FAKE_JOB_SUCCESS_STATE)
        starting_job['state'] = 'starting'
        errored_job = copy.copy(c_fake.FAKE_JOB_SUCCESS_STATE)
        errored_job['state'] = constants.STATUS_ERROR
        returned_jobs = [starting_job, errored_job]

        self.mock_object(self.mock_dest_client, 'get_job',
                         mock.Mock(side_effect=returned_jobs))

        self.assertRaises(
            exception.NetAppException,
            self.library._wait_for_operation_status,
            c_fake.FAKE_JOB_ID,
            self.mock_dest_client.get_job
        )

    @ddt.data(
        {'src_supports_svm_migrate': True, 'dest_supports_svm_migrate': True},
        {'src_supports_svm_migrate': True, 'dest_supports_svm_migrate': False},
        {'src_supports_svm_migrate': False, 'dest_supports_svm_migrate': True},
        {'src_supports_svm_migrate': False, 'dest_supports_svm_migrate': False}
    )
    @ddt.unpack
    def test_share_server_migration_start(self, src_supports_svm_migrate,
                                          dest_supports_svm_migrate):
        fake_migration_data = {'fake_migration_key': 'fake_migration_value'}
        self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(
                side_effect=[(self.fake_src_vserver, self.mock_src_client)]))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=self.mock_dest_client))
        mock_start_using_svm_migrate = self.mock_object(
            self.library, '_migration_start_using_svm_migrate',
            mock.Mock(return_value=fake_migration_data))
        mock_start_using_svm_dr = self.mock_object(
            self.library, '_migration_start_using_svm_dr',
            mock.Mock(return_value=fake_migration_data))

        self.mock_src_client.is_svm_migrate_supported.return_value = (
            src_supports_svm_migrate)
        self.mock_dest_client.is_svm_migrate_supported.return_value = (
            dest_supports_svm_migrate)
        src_and_dest_support_svm_migrate = all(
            [src_supports_svm_migrate, dest_supports_svm_migrate])

        result = self.library.share_server_migration_start(
            None, self.fake_src_share_server, self.fake_dest_share_server,
            [fake.SHARE_INSTANCE], [])

        self.library._get_vserver.assert_called_once_with(
            share_server=self.fake_src_share_server,
            backend_name=self.fake_src_backend_name)
        if src_and_dest_support_svm_migrate:
            mock_start_using_svm_migrate.assert_called_once_with(
                None, self.fake_src_share_server, self.fake_dest_share_server,
                self.mock_src_client, self.mock_dest_client)
        else:
            mock_start_using_svm_dr.assert_called_once_with(
                self.fake_src_share_server, self.fake_dest_share_server
            )
        self.assertEqual(result, fake_migration_data)

    @ddt.data({'vserver_peered': True, 'src_cluster': fake.CLUSTER_NAME},
              {'vserver_peered': False, 'src_cluster': fake.CLUSTER_NAME},
              {'vserver_peered': False, 'src_cluster': fake.CLUSTER_NAME_2})
    @ddt.unpack
    def test__migration_start_using_svm_dr(self, vserver_peered, src_cluster):
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

        self.library._migration_start_using_svm_dr(
            self.fake_src_share_server, self.fake_dest_share_server)

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
                          self.library._migration_start_using_svm_dr,
                          self.fake_src_share_server,
                          self.fake_dest_share_server)

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

    @ddt.data(
        {'network_change_during_migration': True},
        {'network_change_during_migration': False})
    @ddt.unpack
    def test__migration_start_using_svm_migrate(
            self, network_change_during_migration):

        self.fake_src_share_server['share_network_subnet_id'] = 'fake_sns_id'
        self.fake_dest_share_server['share_network_subnet_id'] = 'fake_sns_id'
        node_name = fake.CLUSTER_NODES[0]
        expected_server_info = {
            'backend_details': {
                'migration_operation_id': c_fake.FAKE_MIGRATION_POST_ID
            }
        }

        if not network_change_during_migration:
            self.fake_dest_share_server['network_allocations'] = None
        server_to_get_network_info = (
            self.fake_dest_share_server
            if network_change_during_migration else self.fake_src_share_server)

        if network_change_during_migration:
            self.fake_dest_share_server['share_network_subnet_id'] = (
                'different_sns_id')

        segmentation_id = (
            server_to_get_network_info['network_allocations'][0][
                'segmentation_id'])

        network_info = {
            'network_allocations':
                server_to_get_network_info['network_allocations'],
            'neutron_subnet_id':
                server_to_get_network_info['share_network_subnets'][0].get(
                    'neutron_subnet_id')
        }

        mock_list_cluster_nodes = self.mock_object(
            self.library._client, 'list_cluster_nodes',
            mock.Mock(return_value=fake.CLUSTER_NODES))
        mock_get_data_port = self.mock_object(
            self.library, '_get_node_data_port',
            mock.Mock(return_value=fake.NODE_DATA_PORT))
        mock_get_ipspace = self.mock_object(
            self.library._client, 'get_ipspace_name_for_vlan_port',
            mock.Mock(return_value=fake.IPSPACE))
        mock_create_port = self.mock_object(
            self.library, '_create_port_and_broadcast_domain')
        mock_get_vserver_name = self.mock_object(
            self.library, '_get_vserver_name',
            mock.Mock(return_value=fake.VSERVER1))
        mock_get_cluster_name = self.mock_object(
            self.mock_src_client, 'get_cluster_name',
            mock.Mock(return_value=fake.CLUSTER_NAME))
        mock_get_aggregates = self.mock_object(
            self.library, '_find_matching_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        mock_svm_migration_start = self.mock_object(
            self.mock_dest_client, 'svm_migration_start',
            mock.Mock(return_value=c_fake.FAKE_MIGRATION_RESPONSE_WITH_JOB))
        mock_get_job = self.mock_object(
            self.mock_dest_client, 'get_job',
            mock.Mock(return_value=c_fake.FAKE_JOB_SUCCESS_STATE))

        server_info = self.library._migration_start_using_svm_migrate(
            None, self.fake_src_share_server, self.fake_dest_share_server,
            self.mock_src_client, self.mock_dest_client)

        self.assertTrue(mock_list_cluster_nodes.called)
        mock_get_data_port.assert_called_once_with(node_name)
        mock_get_ipspace.assert_called_once_with(
            node_name, fake.NODE_DATA_PORT, segmentation_id)
        mock_create_port.assert_called_once_with(
            fake.IPSPACE, network_info)
        mock_get_vserver_name.assert_called_once_with(
            self.fake_src_share_server['id'])
        self.assertTrue(mock_get_cluster_name.called)
        mock_svm_migration_start.assert_called_once_with(
            fake.CLUSTER_NAME, fake.VSERVER1, fake.AGGREGATES,
            dest_ipspace=fake.IPSPACE)
        self.assertTrue(mock_get_aggregates.called)
        self.assertEqual(expected_server_info, server_info)
        mock_get_job.assert_called_once_with(c_fake.FAKE_JOB_ID)

    def test__migration_start_using_svm_migrate_exception(self):

        self.fake_src_share_server['share_network_subnet_id'] = 'fake_sns_id'
        self.fake_dest_share_server['share_network_subnet_id'] = 'fake_sns_id'
        node_name = fake.CLUSTER_NODES[0]

        server_to_get_network_info = self.fake_dest_share_server

        segmentation_id = (
            server_to_get_network_info['network_allocations'][0][
                'segmentation_id'])

        network_info = {
            'network_allocations':
                server_to_get_network_info['network_allocations'],
            'neutron_subnet_id':
                server_to_get_network_info['share_network_subnets'][0].get(
                    'neutron_subnet_id')
        }

        mock_list_cluster_nodes = self.mock_object(
            self.library._client, 'list_cluster_nodes',
            mock.Mock(return_value=fake.CLUSTER_NODES))
        mock_get_data_port = self.mock_object(
            self.library, '_get_node_data_port',
            mock.Mock(return_value=fake.NODE_DATA_PORT))
        mock_get_ipspace = self.mock_object(
            self.library._client, 'get_ipspace_name_for_vlan_port',
            mock.Mock(return_value=fake.IPSPACE))
        mock_create_port = self.mock_object(
            self.library, '_create_port_and_broadcast_domain')
        mock_get_vserver_name = self.mock_object(
            self.library, '_get_vserver_name',
            mock.Mock(return_value=fake.VSERVER1))
        mock_get_cluster_name = self.mock_object(
            self.mock_src_client, 'get_cluster_name',
            mock.Mock(return_value=fake.CLUSTER_NAME))
        mock_get_aggregates = self.mock_object(
            self.library, '_find_matching_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        mock_svm_migration_start = self.mock_object(
            self.mock_dest_client, 'svm_migration_start',
            mock.Mock(side_effect=exception.NetAppException()))
        mock_delete_ipspace = self.mock_object(
            self.mock_dest_client, 'delete_ipspace')

        self.assertRaises(
            exception.NetAppException,
            self.library._migration_start_using_svm_migrate,
            None,
            self.fake_src_share_server, self.fake_dest_share_server,
            self.mock_src_client, self.mock_dest_client)

        self.assertTrue(mock_list_cluster_nodes.called)
        mock_get_data_port.assert_called_once_with(node_name)
        mock_get_ipspace.assert_called_once_with(
            node_name, fake.NODE_DATA_PORT, segmentation_id)
        mock_create_port.assert_called_once_with(
            fake.IPSPACE, network_info)
        mock_get_vserver_name.assert_called_once_with(
            self.fake_src_share_server['id'])
        self.assertTrue(mock_get_cluster_name.called)
        mock_svm_migration_start.assert_called_once_with(
            fake.CLUSTER_NAME, fake.VSERVER1, fake.AGGREGATES,
            dest_ipspace=fake.IPSPACE)
        self.assertTrue(mock_get_aggregates.called)
        mock_delete_ipspace.assert_called_once_with(fake.IPSPACE)

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

    def test_share_server_migration_continue_svm_dr_no_snapmirror(self):
        self.mock_object(self.library, '_get_snapmirror_svm',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.NetAppException,
                          self.library._share_server_migration_continue_svm_dr,
                          self.fake_src_share_server,
                          self.fake_dest_share_server)

        self.library._get_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    @ddt.data({'mirror_state': 'snapmirrored', 'status': 'idle'},
              {'mirror_state': 'uninitialized', 'status': 'transferring'},
              {'mirror_state': 'snapmirrored', 'status': 'quiescing'},)
    @ddt.unpack
    def test_share_server_migration_continue_svm_dr(self, mirror_state,
                                                    status):
        fake_snapmirror = {
            'mirror-state': mirror_state,
            'relationship-status': status,
        }
        self.mock_object(self.library, '_get_snapmirror_svm',
                         mock.Mock(return_value=[fake_snapmirror]))
        expected = mirror_state == 'snapmirrored' and status == 'idle'

        result = self.library._share_server_migration_continue_svm_dr(
            self.fake_src_share_server,
            self.fake_dest_share_server
        )

        self.assertEqual(expected, result)
        self.library._get_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    @ddt.data(
        ('ready_for_cutover', True),
        ('transferring', False)
    )
    @ddt.unpack
    def test_share_server_migration_continue_svm_migrate(
            self, job_state, first_phase_completed):
        c_fake.FAKE_MIGRATION_JOB_SUCCESS.update({"state": job_state})

        self.mock_object(data_motion, 'get_client_for_host',
                         mock.Mock(return_value=self.mock_dest_client))
        self.mock_object(
            self.mock_dest_client, 'svm_migration_get',
            mock.Mock(return_value=c_fake.FAKE_MIGRATION_JOB_SUCCESS))

        result = self.library._share_server_migration_continue_svm_migrate(
            self.fake_dest_share_server, c_fake.FAKE_MIGRATION_POST_ID)

        self.assertEqual(first_phase_completed, result)
        data_motion.get_client_for_host.assert_called_once_with(
            self.fake_dest_share_server['host'])
        self.mock_dest_client.svm_migration_get.assert_called_once_with(
            c_fake.FAKE_MIGRATION_POST_ID)

    def test_share_server_migration_continue_svm_migrate_exception(self):

        self.mock_object(data_motion, 'get_client_for_host',
                         mock.Mock(return_value=self.mock_dest_client))
        self.mock_object(self.mock_dest_client, 'svm_migration_get',
                         mock.Mock(side_effect=netapp_api.NaApiError()))

        self.assertRaises(
            exception.NetAppException,
            self.library._share_server_migration_continue_svm_migrate,
            self.fake_dest_share_server, c_fake.FAKE_MIGRATION_POST_ID)

        data_motion.get_client_for_host.assert_called_once_with(
            self.fake_dest_share_server['host'])
        self.mock_dest_client.svm_migration_get.assert_called_once_with(
            c_fake.FAKE_MIGRATION_POST_ID)

    @ddt.data(None, 'fake_migration_id')
    def test_share_server_migration_continue(self, migration_id):
        expected_result = True
        self.mock_object(
            self.library, '_get_share_server_migration_id',
            mock.Mock(return_value=migration_id))
        self.mock_object(
            self.library, '_share_server_migration_continue_svm_migrate',
            mock.Mock(return_value=expected_result))
        self.mock_object(
            self.library, '_share_server_migration_continue_svm_dr',
            mock.Mock(return_value=expected_result))

        result = self.library.share_server_migration_continue(
            None, self.fake_src_share_server, self.fake_dest_share_server,
            [], []
        )

        self.assertEqual(expected_result, result)

    def test__setup_networking_for_destination_vserver(self):
        self.mock_object(self.mock_dest_client, 'get_vserver_ipspace',
                         mock.Mock(return_value=fake.IPSPACE))
        self.mock_object(self.library, '_setup_network_for_vserver')

        self.library._setup_networking_for_destination_vserver(
            self.mock_dest_client, self.fake_vserver,
            fake.NETWORK_INFO_LIST)

        self.mock_dest_client.get_vserver_ipspace.assert_called_once_with(
            self.fake_vserver)
        self.library._setup_network_for_vserver.assert_called_once_with(
            self.fake_vserver, self.mock_dest_client, fake.NETWORK_INFO_LIST,
            fake.IPSPACE, enable_nfs=False, security_services=None)

    def test__migration_complete_svm_dr(self):
        dm_session_mock = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(self.fake_dest_vserver,
                                                 self.mock_dest_client)))
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(
            self.library, '_setup_networking_for_destination_vserver')

        self.library._share_server_migration_complete_svm_dr(
            self.fake_src_share_server, self.fake_dest_share_server,
            self.fake_src_vserver, self.mock_src_client,
            [fake.SHARE_INSTANCE], fake.NETWORK_INFO_LIST
        )

        self.library._get_vserver.assert_called_once_with(
            share_server=self.fake_dest_share_server,
            backend_name=self.fake_dest_backend_name
        )
        dm_session_mock.update_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
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
        (self.library._setup_networking_for_destination_vserver
            .assert_called_once_with(
                self.mock_dest_client, self.fake_dest_vserver,
                fake.NETWORK_INFO_LIST))
        self.mock_dest_client.start_vserver.assert_called_once_with(
            self.fake_dest_vserver
        )
        dm_session_mock.delete_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    @ddt.data(
        {'is_svm_dr': True, 'network_change': True},
        {'is_svm_dr': False, 'network_change': True},
        {'is_svm_dr': False, 'network_change': False},
    )
    @ddt.unpack
    def test_share_server_migration_complete(self, is_svm_dr, network_change):
        current_interfaces = ['interface_1', 'interface_2']
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=[
                             (self.fake_src_vserver, self.mock_src_client),
                             (self.fake_dest_vserver, self.mock_dest_client)]))
        mock_complete_svm_migrate = self.mock_object(
            self.library, '_share_server_migration_complete_svm_migrate')
        mock_complete_svm_dr = self.mock_object(
            self.library, '_share_server_migration_complete_svm_dr')
        fake_share_name = self.library._get_backend_share_name(
            fake.SHARE_INSTANCE['id'])
        fake_volume = copy.deepcopy(fake.CLIENT_GET_VOLUME_RESPONSE)
        self.mock_object(self.mock_dest_client, 'get_volume',
                         mock.Mock(return_value=fake_volume))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value=fake.NFS_EXPORTS))
        self.mock_object(self.library, '_delete_share')
        mock_update_share_attrs = self.mock_object(
            self.library, '_update_share_attributes_after_server_migration')
        self.mock_object(data_motion, 'get_client_for_host',
                         mock.Mock(return_value=self.mock_dest_client))
        self.mock_object(self.mock_dest_client, 'list_network_interfaces',
                         mock.Mock(return_value=current_interfaces))
        self.mock_object(self.mock_dest_client, 'delete_network_interface')
        self.mock_object(self.library,
                         '_setup_networking_for_destination_vserver')

        sns_id = 'fake_sns_id'
        new_sns_id = 'fake_sns_id_2'
        self.fake_src_share_server['share_network_subnet_id'] = sns_id
        self.fake_dest_share_server['share_network_subnet_id'] = (
            sns_id if not network_change else new_sns_id)
        share_instances = [fake.SHARE_INSTANCE]
        migration_id = 'fake_migration_id'
        share_host = fake.SHARE_INSTANCE['host']
        self.fake_src_share_server['backend_details']['ports'] = []

        if not is_svm_dr:
            self.fake_dest_share_server['backend_details'][
                'migration_operation_id'] = (
                migration_id)
            share_host = share_host.replace(
                share_host.split('#')[1], fake_volume['aggregate'])
        should_recreate_export = is_svm_dr or network_change
        share_server_to_get_vserver_name = (
            self.fake_dest_share_server
            if is_svm_dr else self.fake_src_share_server)

        result = self.library.share_server_migration_complete(
            None,
            self.fake_src_share_server,
            self.fake_dest_share_server,
            share_instances, [],
            fake.NETWORK_INFO_LIST
        )

        expected_share_updates = {
            fake.SHARE_INSTANCE['id']: {
                'pool_name': fake_volume['aggregate']
            }
        }
        expected_share_updates[fake.SHARE_INSTANCE['id']].update(
            {'export_locations': fake.NFS_EXPORTS})
        expected_backend_details = (
            {} if is_svm_dr else self.fake_src_share_server['backend_details'])
        expected_result = {
            'share_updates': expected_share_updates,
            'server_backend_details': expected_backend_details
        }

        self.assertEqual(expected_result, result)
        self.library._get_vserver.assert_has_calls([
            mock.call(share_server=self.fake_src_share_server,
                      backend_name=self.fake_src_backend_name),
            mock.call(share_server=share_server_to_get_vserver_name,
                      backend_name=self.fake_dest_backend_name)])
        if is_svm_dr:
            mock_complete_svm_dr.assert_called_once_with(
                self.fake_src_share_server, self.fake_dest_share_server,
                self.fake_src_vserver, self.mock_src_client,
                share_instances, fake.NETWORK_INFO_LIST
            )
            self.library._delete_share.assert_called_once_with(
                fake.SHARE_INSTANCE, self.fake_src_vserver,
                self.mock_src_client, remove_export=True)
            mock_update_share_attrs.assert_called_once_with(
                fake.SHARE_INSTANCE, self.mock_src_client,
                fake_volume['aggregate'], self.mock_dest_client)
        else:
            mock_complete_svm_migrate.assert_called_once_with(
                migration_id, self.fake_dest_share_server)
            self.mock_dest_client.list_network_interfaces.assert_called_once()
            data_motion.get_client_for_host.assert_called_once_with(
                self.fake_dest_share_server['host'])
            self.mock_dest_client.delete_network_interface.assert_has_calls(
                [mock.call(self.fake_src_vserver, interface_name)
                 for interface_name in current_interfaces])
            (self.library._setup_networking_for_destination_vserver.
                assert_called_once_with(self.mock_dest_client,
                                        self.fake_src_vserver,
                                        fake.NETWORK_INFO_LIST))
        if should_recreate_export:
            create_export_calls = [
                mock.call(
                    instance, self.fake_dest_share_server,
                    self.fake_dest_vserver, self.mock_dest_client,
                    clear_current_export_policy=False,
                    ensure_share_already_exists=True,
                    share_host=share_host)
                for instance in share_instances
            ]
            self.library._create_export.assert_has_calls(create_export_calls)
        self.mock_dest_client.get_volume.assert_called_once_with(
            fake_share_name)

    def test_share_server_migration_complete_failure_breaking(self):
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(self.fake_dest_vserver,
                                    self.mock_dest_client)))
        self.mock_object(dm_session_mock, 'quiesce_and_break_snapmirror_svm',
                         mock.Mock(side_effect=exception.NetAppException))
        self.mock_object(self.library, '_delete_share')

        self.assertRaises(exception.NetAppException,
                          self.library._share_server_migration_complete_svm_dr,
                          self.fake_src_share_server,
                          self.fake_dest_share_server,
                          self.fake_src_vserver,
                          self.mock_src_client, [fake.SHARE_INSTANCE],
                          [fake.NETWORK_INFO])

        dm_session_mock.update_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        self.library._get_vserver.assert_called_once_with(
            share_server=self.fake_dest_share_server,
            backend_name=self.fake_dest_backend_name)
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
            fake.SHARE_INSTANCE, self.fake_dest_vserver, self.mock_dest_client,
            remove_export=False)

    def test_share_server_migration_complete_failure_get_new_volume(self):
        dm_session_mock = mock.Mock()
        fake_share_name = self.library._get_backend_share_name(
            fake.SHARE_INSTANCE['id'])
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=[
                             (self.fake_src_vserver, self.mock_src_client),
                             (self.fake_dest_vserver, self.mock_dest_client)]))
        self.mock_object(self.library,
                         '_share_server_migration_complete_svm_dr')
        self.mock_object(self.library, '_get_share_server_migration_id',
                         mock.Mock(return_value=None))
        self.mock_object(self.mock_dest_client, 'get_volume',
                         mock.Mock(side_effect=exception.NetAppException))

        self.assertRaises(exception.NetAppException,
                          self.library.share_server_migration_complete,
                          None,
                          self.fake_src_share_server,
                          self.fake_dest_share_server,
                          [fake.SHARE_INSTANCE], [],
                          fake.NETWORK_INFO_LIST)

        self.library._get_vserver.assert_has_calls([
            mock.call(share_server=self.fake_src_share_server,
                      backend_name=self.fake_src_backend_name),
            mock.call(share_server=self.fake_dest_share_server,
                      backend_name=self.fake_dest_backend_name)])
        self.mock_dest_client.get_volume.assert_called_once_with(
            fake_share_name)

    def test__share_server_migration_complete_svm_migrate(self):
        completion_status = na_utils.MIGRATION_STATE_MIGRATE_COMPLETE
        migration_id = 'fake_migration_id'
        fake_complete_job_uuid = 'fake_uuid'
        fake_complete_job = {
            'job': {
                'state': 'cutover_triggered',
                'uuid': fake_complete_job_uuid
            }
        }
        self.mock_object(data_motion, 'get_client_for_host',
                         mock.Mock(return_value=self.mock_dest_client))
        self.mock_object(self.mock_dest_client, 'svm_migrate_complete',
                         mock.Mock(return_value=fake_complete_job))
        self.mock_object(self.library, '_get_job_uuid',
                         mock.Mock(return_value=fake_complete_job_uuid))
        self.mock_object(self.library, '_wait_for_operation_status')

        self.library._share_server_migration_complete_svm_migrate(
            migration_id, self.fake_dest_share_server)

        data_motion.get_client_for_host.assert_called_once_with(
            self.fake_dest_share_server['host'])
        self.mock_dest_client.svm_migrate_complete.assert_called_once_with(
            migration_id)
        self.library._get_job_uuid.assert_called_once_with(fake_complete_job)
        self.library._wait_for_operation_status.assert_has_calls(
            [mock.call(fake_complete_job_uuid, self.mock_dest_client.get_job),
             mock.call(migration_id, self.mock_dest_client.svm_migration_get,
                       desired_status=completion_status)
             ]
        )

    def test__share_server_migration_complete_svm_migrate_failed_to_complete(
            self):
        migration_id = 'fake_migration_id'

        self.mock_object(data_motion, 'get_client_for_host',
                         mock.Mock(return_value=self.mock_dest_client))
        self.mock_object(self.mock_dest_client, 'svm_migrate_complete',
                         mock.Mock(side_effect=exception.NetAppException()))

        self.assertRaises(
            exception.NetAppException,
            self.library._share_server_migration_complete_svm_migrate,
            migration_id, self.fake_dest_share_server)

        data_motion.get_client_for_host.assert_called_once_with(
            self.fake_dest_share_server['host'])
        self.mock_dest_client.svm_migrate_complete.assert_called_once_with(
            migration_id)

    @ddt.data([], ['fake_snapmirror'])
    def test_share_server_migration_cancel_svm_dr(self, snapmirrors):
        dm_session_mock = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=dm_session_mock))
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(self.fake_dest_vserver,
                                                 self.mock_dest_client)))
        self.mock_object(self.library, '_get_snapmirror_svm',
                         mock.Mock(return_value=snapmirrors))
        self.mock_object(self.library, '_delete_share')

        self.library._migration_cancel_using_svm_dr(
            self.fake_src_share_server,
            self.fake_dest_share_server,
            [fake.SHARE_INSTANCE]
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
            fake.SHARE_INSTANCE, self.fake_dest_vserver, self.mock_dest_client,
            remove_export=False)

    @ddt.data(True, False)
    def test__migration_cancel_using_svm_migrate(self, has_ipspace):
        pause_job_uuid = 'fake_pause_job_id'
        cancel_job_uuid = 'fake_cancel_job_id'
        ipspace_name = 'fake_ipspace_name'
        migration_id = 'fake_migration_id'
        pause_job = {
            'uuid': pause_job_uuid
        }
        cancel_job = {
            'uuid': cancel_job_uuid
        }
        migration_information = {
            "destination": {
                "ipspace": {
                    "name": ipspace_name
                }
            }
        }

        if has_ipspace:
            migration_information["destination"]["ipspace"]["name"] = (
                ipspace_name)

        self.mock_object(self.library, '_get_job_uuid',
                         mock.Mock(
                             side_effect=[pause_job_uuid, cancel_job_uuid]))
        self.mock_object(data_motion, 'get_client_for_host',
                         mock.Mock(return_value=self.mock_dest_client))
        self.mock_object(self.mock_dest_client, 'svm_migration_get',
                         mock.Mock(return_value=migration_information))
        self.mock_object(self.mock_dest_client, 'svm_migrate_pause',
                         mock.Mock(return_value=pause_job))
        self.mock_object(self.library, '_wait_for_operation_status')
        self.mock_object(self.mock_dest_client, 'svm_migrate_cancel',
                         mock.Mock(return_value=cancel_job))
        self.mock_object(self.mock_dest_client, 'ipspace_has_data_vservers',
                         mock.Mock(return_value=False))
        self.mock_object(self.mock_dest_client, 'delete_ipspace')

        self.library._migration_cancel_using_svm_migrate(
            migration_id, self.fake_dest_share_server)

        self.library._get_job_uuid.assert_has_calls(
            [mock.call(pause_job), mock.call(cancel_job)]
        )
        data_motion.get_client_for_host.assert_called_once_with(
            self.fake_dest_share_server['host'])
        self.mock_dest_client.svm_migration_get.assert_called_once_with(
            migration_id)
        self.mock_dest_client.svm_migrate_pause.assert_called_once_with(
            migration_id)
        self.library._wait_for_operation_status.assert_has_calls(
            [mock.call(pause_job_uuid, self.mock_dest_client.get_job),
             mock.call(migration_id, self.mock_dest_client.svm_migration_get,
                       desired_status=na_utils.MIGRATION_STATE_MIGRATE_PAUSED),
             mock.call(cancel_job_uuid, self.mock_dest_client.get_job)]
        )
        self.mock_dest_client.svm_migrate_cancel.assert_called_once_with(
            migration_id)

        if has_ipspace:
            self.mock_dest_client.delete_ipspace.assert_called_once_with(
                ipspace_name)

    @ddt.data(
        (mock.Mock(side_effect=exception.NetAppException()), mock.Mock()),
        (mock.Mock(), mock.Mock(side_effect=exception.NetAppException()))
    )
    @ddt.unpack
    def test__migration_cancel_using_svm_migrate_error(
            self, mock_pause, mock_cancel):
        pause_job_uuid = 'fake_pause_job_id'
        cancel_job_uuid = 'fake_cancel_job_id'
        migration_id = 'fake_migration_id'
        migration_information = {
            "destination": {
                "ipspace": {
                    "name": "ipspace_name"
                }
            }
        }

        self.mock_object(self.library, '_get_job_uuid',
                         mock.Mock(
                             side_effect=[pause_job_uuid, cancel_job_uuid]))
        self.mock_object(data_motion, 'get_client_for_host',
                         mock.Mock(return_value=self.mock_dest_client))
        self.mock_object(self.mock_dest_client, 'svm_migration_get',
                         mock.Mock(return_value=migration_information))
        self.mock_object(self.mock_dest_client, 'svm_migrate_pause',
                         mock_pause)
        self.mock_object(self.library, '_wait_for_operation_status')
        self.mock_object(self.mock_dest_client, 'svm_migrate_cancel',
                         mock_cancel)

        self.assertRaises(
            exception.NetAppException,
            self.library._migration_cancel_using_svm_migrate,
            migration_id,
            self.fake_dest_share_server
        )

    def test_share_server_migration_cancel_svm_dr_snapmirror_failure(self):
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
                          self.library._migration_cancel_using_svm_dr,
                          self.fake_src_share_server,
                          self.fake_dest_share_server,
                          [fake.SHARE_INSTANCE])

        self.library._get_vserver.assert_called_once_with(
            share_server=self.fake_dest_share_server,
            backend_name=self.fake_dest_backend_name)
        self.library._get_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )
        dm_session_mock.cancel_snapmirror_svm.assert_called_once_with(
            self.fake_src_share_server, self.fake_dest_share_server
        )

    @ddt.data(None, 'fake_migration_id')
    def test_share_server_migration_cancel(self, migration_id):
        self.mock_object(self.library, '_get_share_server_migration_id',
                         mock.Mock(return_value=migration_id))
        self.mock_object(self.library, '_migration_cancel_using_svm_migrate')
        self.mock_object(self.library, '_migration_cancel_using_svm_dr')

        self.library.share_server_migration_cancel(
            None, self.fake_src_share_server, self.fake_dest_share_server,
            [], [])

        if migration_id:
            (self.library._migration_cancel_using_svm_migrate
                .assert_called_once_with(
                    migration_id, self.fake_dest_share_server))
        else:
            (self.library._migration_cancel_using_svm_dr
                .assert_called_once_with(
                    self.fake_src_share_server, self.fake_dest_share_server,
                    []))

    def test_share_server_migration_get_progress(self):
        fake_vserver_name = fake.VSERVER1
        expected_result = {'total_progress': 50}

        self.mock_object(self.library._client, 'get_svm_volumes_total_size',
                         mock.Mock(return_value=5))

        self.mock_object(self.library, '_get_vserver_name',
                         mock.Mock(return_value=fake_vserver_name))

        result = self.library.share_server_migration_get_progress(
            None, self.fake_src_share_server, self.fake_dest_share_server,
            [self.fake_src_share], None
        )

        self.library._client.get_svm_volumes_total_size.assert_called_once_with
        (fake_vserver_name)
        self.library._get_vserver_name.assert_called_once_with
        (self.fake_dest_share_server['source_share_server_id'])
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
        mock_get_extra_spec = self.mock_object(
            share_types, 'get_extra_specs_from_share',
            mock.Mock(return_value='fake_extra_specs'))
        mock_get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options',
            mock.Mock(return_value={}))
        self.mock_object(mock_client, 'list_vserver_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))

        result = self.library.choose_share_server_compatible_with_share(
            None, [fake.SHARE_SERVER], fake.SHARE_2,
            None, share_group
        )
        expected_result = fake.SHARE_SERVER if compatible else None
        self.assertEqual(expected_result, result)
        mock_get_extra_spec.assert_called_once_with(fake.SHARE_2)
        mock_get_provisioning_opts.assert_called_once_with('fake_extra_specs')
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

    @ddt.data(
        {'policies': [], 'reusable_scope': None, 'compatible': True},
        {'policies': "0123456789", 'reusable_scope': {'scope'},
         'compatible': True},
        {'policies': "0123456789", 'reusable_scope': None,
         'compatible': False})
    @ddt.unpack
    def test_choose_share_server_compatible_with_share_fpolicy(
            self, policies, reusable_scope, compatible):
        self.library.is_nfs_config_supported = False
        mock_client = mock.Mock()
        fake_extra_spec = copy.deepcopy(fake.EXTRA_SPEC_WITH_FPOLICY)
        mock_get_extra_spec = self.mock_object(
            share_types, 'get_extra_specs_from_share',
            mock.Mock(return_value=fake_extra_spec))
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock_client)))
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(mock_client, 'list_vserver_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_get_policies = self.mock_object(
            mock_client, 'get_fpolicy_policies_status',
            mock.Mock(return_value=policies))
        mock_reusable_scope = self.mock_object(
            self.library, '_find_reusable_fpolicy_scope',
            mock.Mock(return_value=reusable_scope))

        result = self.library.choose_share_server_compatible_with_share(
            None, [fake.SHARE_SERVER], fake.SHARE_2,
            None, None
        )

        expected_result = fake.SHARE_SERVER if compatible else None
        self.assertEqual(expected_result, result)
        mock_get_extra_spec.assert_called_once_with(fake.SHARE_2)
        mock_client.get_vserver_info.assert_called_once_with(
            fake.VSERVER1,
        )
        self.library._get_vserver.assert_called_once_with(
            fake.SHARE_SERVER, backend_name=fake.BACKEND_NAME
        )
        mock_get_policies.assert_called_once()
        if len(policies) >= self.library.FPOLICY_MAX_VSERVER_POLICIES:
            mock_reusable_scope.assert_called_once_with(
                fake.SHARE_2, mock_client,
                fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
                fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
                fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS)

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

    def test_choose_share_server_compatible_with_different_aggrs(self):
        self.library.is_nfs_config_supported = False
        mock_client = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock_client)))
        fake_vserver_info = {
            'operational_state': 'running',
            'state': 'running',
            'subtype': 'default'
        }
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake_vserver_info))
        mock_get_extra_spec = self.mock_object(
            share_types, 'get_extra_specs_from_share',
            mock.Mock(return_value='fake_extra_specs'))
        mock_get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options',
            mock.Mock(return_value={}))
        self.mock_object(mock_client, 'list_vserver_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        result = self.library.choose_share_server_compatible_with_share(
            None, [fake.SHARE_SERVER], fake.SHARE_INSTANCE, None)
        self.assertIsNone(result)
        mock_get_extra_spec.assert_called_once_with(fake.SHARE_INSTANCE)
        mock_get_provisioning_opts.assert_called_once_with('fake_extra_specs')

    def test_choose_share_server_compatible_with_flexgroups(self):
        self.library.is_nfs_config_supported = False
        mock_client = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock_client)))
        fake_vserver_info = {
            'operational_state': 'running',
            'state': 'running',
            'subtype': 'default'
        }
        self.mock_object(mock_client, 'get_vserver_info',
                         mock.Mock(return_value=fake_vserver_info))
        mock_get_extra_spec = self.mock_object(
            share_types, 'get_extra_specs_from_share',
            mock.Mock(return_value='fake_extra_specs'))
        mock_get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options',
            mock.Mock(return_value={}))
        self.mock_object(mock_client, 'list_vserver_aggregates',
                         mock.Mock(return_value=fake.FLEXGROUP_POOL_AGGR))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=True))
        self.mock_object(self.library, '_get_flexgroup_aggregate_list',
                         mock.Mock(return_value=fake.FLEXGROUP_POOL_AGGR))
        result = self.library.choose_share_server_compatible_with_share(
            None, [fake.SHARE_SERVER], fake.SHARE_FLEXGROUP, None)
        expected_result = fake.SHARE_SERVER
        self.assertEqual(expected_result, result)
        self.library._get_vserver.assert_called_once_with(
            fake.SHARE_SERVER, backend_name=fake.BACKEND_NAME
        )
        mock_client.get_vserver_info.assert_called_once_with(
            fake.VSERVER1,
        )
        mock_get_extra_spec.assert_called_once_with(fake.SHARE_FLEXGROUP)
        mock_get_provisioning_opts.assert_called_once_with('fake_extra_specs')

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

    def test__get_different_keys_for_equal_ss_type(self):
        curr_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        new_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_2)
        new_sec_service2 = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_3)

        expected_keys = ['password', 'user', 'ou',
                         'domain', 'dns_ip', 'server']

        result = self.library._get_different_keys_for_equal_ss_type(
            curr_sec_service, new_sec_service)

        self.assertEqual(expected_keys, result)

        expected_keys = ['password', 'user', 'ou',
                         'domain', 'dns_ip', 'server', 'default_ad_site']
        result = self.library._get_different_keys_for_equal_ss_type(
            curr_sec_service, new_sec_service2)

        self.assertEqual(expected_keys, result)

    @ddt.data(
        {'current': None,
         'new': fake.CIFS_SECURITY_SERVICE,
         'existing': []},

        {'current': fake.CIFS_SECURITY_SERVICE,
         'new': fake.CIFS_SECURITY_SERVICE_2,
         'existing': [fake.CIFS_SECURITY_SERVICE,
                      fake.KERBEROS_SECURITY_SERVICE]},

        {'current': fake.KERBEROS_SECURITY_SERVICE,
         'new': fake.KERBEROS_SECURITY_SERVICE_2,
         'existing': [fake.CIFS_SECURITY_SERVICE,
                      fake.KERBEROS_SECURITY_SERVICE]},

        {'current': fake.CIFS_SECURITY_SERVICE,
         'new': fake.CIFS_SECURITY_SERVICE,
         'existing': [fake.CIFS_SECURITY_SERVICE]},
    )
    @ddt.unpack
    def test_update_share_server_security_service(self, current, new,
                                                  existing):
        fake_context = mock.Mock()
        fake_net_info = copy.deepcopy(fake.NETWORK_INFO_LIST)
        new_sec_service = copy.deepcopy(new)
        curr_sec_service = copy.deepcopy(current) if current else None
        new_type = new_sec_service['type'].lower()
        fake_net_info[0]['security_services'] = existing

        if curr_sec_service:
            # domain modification aren't support
            new_sec_service['domain'] = curr_sec_service['domain']

        different_keys = []
        if curr_sec_service != new_sec_service:
            different_keys = ['dns_ip', 'server', 'domain', 'user', 'password']
            if new_sec_service.get('ou') is not None:
                different_keys.append('ou')

        fake_vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=[fake.VSERVER1, fake_vserver_client]))
        mock_check_update = self.mock_object(
            self.library, 'check_update_share_server_security_service',
            mock.Mock(return_value=True))
        mock_setup_sec_serv = self.mock_object(
            self.library._client, 'setup_security_services')
        mock_diff_keys = self.mock_object(
            self.library, '_get_different_keys_for_equal_ss_type',
            mock.Mock(return_value=different_keys))
        mock_dns_update = self.mock_object(
            fake_vserver_client, 'update_dns_configuration')
        mock_update_krealm = self.mock_object(
            fake_vserver_client, 'update_kerberos_realm')
        mock_modify_ad = self.mock_object(
            fake_vserver_client, 'modify_active_directory_security_service')

        self.library.update_share_server_security_service(
            fake_context, fake.SHARE_SERVER, fake_net_info,
            new_sec_service, current_security_service=curr_sec_service)

        dns_ips = set()
        domains = set()
        # we don't need to split and strip since we know that fake have only
        # on dns-ip and domain configured
        for ss in existing:
            if ss['type'] != new_sec_service['type']:
                dns_ips.add(ss['dns_ip'])
                domains.add(ss['domain'])
        dns_ips.add(new_sec_service['dns_ip'])
        domains.add(new_sec_service['domain'])

        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)
        mock_check_update.assert_called_once_with(
            fake_context, fake.SHARE_SERVER, fake_net_info, new_sec_service,
            current_security_service=curr_sec_service)

        if curr_sec_service is None:
            mock_setup_sec_serv.assert_called_once_with(
                [new_sec_service], fake_vserver_client, fake.VSERVER1)
        else:
            mock_diff_keys.assert_called_once_with(curr_sec_service,
                                                   new_sec_service)
            if different_keys:
                mock_dns_update.assert_called_once_with(dns_ips, domains)
                if new_type == 'kerberos':
                    mock_update_krealm.assert_called_once_with(new_sec_service)
                elif new_type == 'active_directory':
                    mock_modify_ad.assert_called_once_with(
                        fake.VSERVER1, different_keys, new_sec_service,
                        curr_sec_service)

    def test_update_share_server_security_service_check_error(self):
        curr_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        new_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_2)
        fake_vserver_client = mock.Mock()
        fake_context = mock.Mock()
        fake_net_info = mock.Mock()

        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=[fake.VSERVER1, fake_vserver_client]))
        mock_check_update = self.mock_object(
            self.library, 'check_update_share_server_security_service',
            mock.Mock(return_value=False))

        self.assertRaises(
            exception.NetAppException,
            self.library.update_share_server_security_service,
            fake_context, fake.SHARE_SERVER, fake_net_info,
            new_sec_service, current_security_service=curr_sec_service)

        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)
        mock_check_update.assert_called_once_with(
            fake_context, fake.SHARE_SERVER, fake_net_info,
            new_sec_service, current_security_service=curr_sec_service)

    @ddt.data(
        {'new': fake.LDAP_AD_SECURITY_SERVICE,
         'current': fake.LDAP_LINUX_SECURITY_SERVICE,
         'expected': True},

        {'new': fake.CIFS_SECURITY_SERVICE,
         'current': fake.KERBEROS_SECURITY_SERVICE,
         'expected': False},

        {'new': fake.CIFS_SECURITY_SERVICE,
         'current': fake.CIFS_SECURITY_SERVICE,
         'expected': True},

        {'new': fake.KERBEROS_SECURITY_SERVICE,
         'current': fake.KERBEROS_SECURITY_SERVICE,
         'expected': True},

        {'new': fake.CIFS_SECURITY_SERVICE,
         'current': None,
         'expected': True},
    )
    @ddt.unpack
    def test_check_update_share_server_security_service(self, new, current,
                                                        expected):
        result = self.library.check_update_share_server_security_service(
            None, None, None, new, current_security_service=current)

        self.assertEqual(expected, result)

    def test_check_update_share_server_network_allocations(self):
        net_alloc_seg_id = fake.USER_NETWORK_ALLOCATIONS[0]['segmentation_id']
        network_segments = [
            {'segmentation_id': net_alloc_seg_id},
            {'segmentation_id': fake.SHARE_NETWORK_SUBNET['segmentation_id']}
        ]

        mock__validate_network_type = self.mock_object(
            self.library, '_validate_network_type')
        mock__validate_share_network_subnets = self.mock_object(
            self.library, '_validate_share_network_subnets')

        result = self.library.check_update_share_server_network_allocations(
            None, fake.SHARE_SERVER, fake.CURRENT_NETWORK_ALLOCATIONS,
            fake.SHARE_NETWORK_SUBNET, None, None,
            None)

        self.assertTrue(result)
        mock__validate_network_type.assert_called_once_with(
            [fake.SHARE_NETWORK_SUBNET])
        mock__validate_share_network_subnets.assert_called_once_with(
            network_segments)

    def test_check_update_share_server_network_allocations_fail_on_type(self):
        network_exception = exception.NetworkBadConfigurationException(
            reason='fake exception message')

        mock_validate_network_type = self.mock_object(
            self.library, '_validate_network_type',
            mock.Mock(side_effect=network_exception))

        mock_validate_share_network_subnets = self.mock_object(
            self.library, '_validate_share_network_subnets')

        result = self.library.check_update_share_server_network_allocations(
            None, fake.SHARE_SERVER, fake.CURRENT_NETWORK_ALLOCATIONS,
            fake.SHARE_NETWORK_SUBNET, None, None, None)

        self.assertFalse(result)
        mock_validate_network_type.assert_called_once_with(
            [fake.SHARE_NETWORK_SUBNET])
        mock_validate_share_network_subnets.assert_not_called()

    def test_check_update_share_server_network_allocations_subnets_error(self):
        net_alloc_seg_id = fake.USER_NETWORK_ALLOCATIONS[0]['segmentation_id']
        network_segments = [
            {'segmentation_id': net_alloc_seg_id},
            {'segmentation_id': fake.SHARE_NETWORK_SUBNET['segmentation_id']}
        ]
        network_exception = exception.NetworkBadConfigurationException(
            reason='fake exception message')

        mock__validate_network_type = self.mock_object(
            self.library, '_validate_network_type')
        mock__validate_share_network_subnets = self.mock_object(
            self.library, '_validate_share_network_subnets',
            mock.Mock(side_effect=network_exception))

        result = self.library.check_update_share_server_network_allocations(
            None, fake.SHARE_SERVER, fake.CURRENT_NETWORK_ALLOCATIONS,
            fake.SHARE_NETWORK_SUBNET, None, None,
            None)

        self.assertFalse(result)
        mock__validate_network_type.assert_called_once_with(
            [fake.SHARE_NETWORK_SUBNET])
        mock__validate_share_network_subnets.assert_called_once_with(
            network_segments)

    @ddt.data(True, False)
    def test_build_model_update(self, has_export_locations):
        server_model_update = copy.deepcopy(fake.SERVER_MODEL_UPDATE)

        export_locations = server_model_update['share_updates']
        if not has_export_locations:
            export_locations = None
            del server_model_update['share_updates']

        result = self.library._build_model_update(
            fake.CURRENT_NETWORK_ALLOCATIONS, fake.NEW_NETWORK_ALLOCATIONS,
            export_locations=export_locations)

        self.assertEqual(server_model_update, result)

    @ddt.data('active', 'dr')
    def test_update_share_server_network_allocations(self, replica_state):
        fake_context = mock.Mock()
        fake_share_server = fake.SHARE_SERVER
        fake_current_network_allocations = fake.USER_NETWORK_ALLOCATIONS
        fake_new_network_allocations = fake.USER_NETWORK_ALLOCATIONS
        fake_share_instances = [copy.deepcopy(fake.SHARE_INSTANCE)]
        fake_share_instances[0]['replica_state'] = replica_state
        fake_vserver_name = fake.VSERVER1
        fake_vserver_client = mock.Mock()
        fake_ipspace_name = fake.IPSPACE
        fake_export_locations = fake.NFS_EXPORTS[0]
        fake_updates = fake.SERVER_MODEL_UPDATE
        fake_updated_export_locations = {
            fake_share_instances[0]['id']: fake_export_locations,
        }

        self.mock_object(self.library, '_get_vserver_name',
                         mock.Mock(return_value=fake_vserver_name))
        self.mock_object(self.library, '_get_api_client',
                         mock.Mock(return_value=fake_vserver_client))
        self.mock_object(self.library._client, 'get_vserver_ipspace',
                         mock.Mock(return_value=fake_ipspace_name))
        self.mock_object(self.library, '_setup_network_for_vserver')
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value=fake_export_locations))
        self.mock_object(self.library, '_build_model_update',
                         mock.Mock(return_value=fake_updates))

        self.assertEqual(
            fake_updates,
            self.library.update_share_server_network_allocations(
                fake_context, fake_share_server,
                fake_current_network_allocations, fake_new_network_allocations,
                None, fake_share_instances, None))
        self.library._get_vserver_name.assert_called_once_with(
            fake_share_server['id'])
        self.library._get_api_client.assert_called_once_with(
            vserver=fake_vserver_name)
        self.library._client.get_vserver_ipspace.assert_called_once_with(
            fake_vserver_name)
        self.library._setup_network_for_vserver.assert_called_once_with(
            fake_vserver_name, fake_vserver_client,
            [fake_new_network_allocations], fake_ipspace_name,
            enable_nfs=False, security_services=None, nfs_config=None)
        if replica_state == 'active':
            self.library._create_export.assert_called_once_with(
                fake_share_instances[0], fake_share_server,
                fake_vserver_name, fake_vserver_client,
                clear_current_export_policy=False,
                ensure_share_already_exists=True,
                share_host=fake_share_instances[0]['host'])
        else:
            self.library._create_export.assert_not_called()
            fake_updated_export_locations = {}

        self.library._build_model_update.assert_called_once_with(
            fake_current_network_allocations, fake_new_network_allocations,
            fake_updated_export_locations)

    def test_update_share_server_network_allocations_setup_network_fail(self):
        fake_context = mock.Mock()
        fake_share_server = fake.SHARE_SERVER
        fake_current_network_allocations = fake.USER_NETWORK_ALLOCATIONS
        fake_new_network_allocations = fake.USER_NETWORK_ALLOCATIONS
        fake_share_instances = [fake.SHARE_INSTANCE]
        fake_updates = fake.SERVER_MODEL_UPDATE

        self.mock_object(self.library, '_get_vserver_name')
        self.mock_object(self.library, '_get_api_client')
        self.mock_object(self.library._client, 'get_vserver_ipspace')
        self.mock_object(self.library, '_setup_network_for_vserver',
                         mock.Mock(side_effect=netapp_api.NaApiError))
        self.mock_object(self.library, '_build_model_update',
                         mock.Mock(return_value=fake_updates))

        self.assertRaises(netapp_api.NaApiError,
                          self.library.update_share_server_network_allocations,
                          fake_context, fake_share_server,
                          fake_current_network_allocations,
                          fake_new_network_allocations, None,
                          fake_share_instances, None)
        self.library._build_model_update.assert_called_once_with(
            fake_current_network_allocations, fake_new_network_allocations,
            export_locations=None)
