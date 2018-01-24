# Copyright (c) 2015 Clinton Knight.  All rights reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
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
Unit tests for the NetApp Data ONTAP cDOT base storage driver library.
"""

import copy
import json
import math
import socket
import time

import ddt
import mock
from oslo_log import log
from oslo_service import loopingcall
from oslo_utils import timeutils
from oslo_utils import units
from oslo_utils import uuidutils

from manila.common import constants
from manila import exception
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.cluster_mode import data_motion
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_base
from manila.share.drivers.netapp.dataontap.cluster_mode import performance
from manila.share.drivers.netapp.dataontap.protocols import cifs_cmode
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila.share.drivers.netapp import utils as na_utils
from manila.share import share_types
from manila.share import utils as share_utils
from manila import test
from manila.tests import fake_share
from manila.tests.share.drivers.netapp.dataontap import fakes as fake
from manila.tests import utils


def fake_replica(**kwargs):
    return fake_share.fake_replica(for_manager=True, **kwargs)


@ddt.ddt
class NetAppFileStorageLibraryTestCase(test.TestCase):

    def setUp(self):
        super(NetAppFileStorageLibraryTestCase, self).setUp()

        self.mock_object(na_utils, 'validate_driver_instantiation')
        self.mock_object(na_utils, 'setup_tracing')

        # Mock loggers as themselves to allow logger arg validation
        mock_logger = log.getLogger('mock_logger')
        self.mock_object(lib_base.LOG,
                         'info',
                         mock.Mock(side_effect=mock_logger.info))
        self.mock_object(lib_base.LOG,
                         'warning',
                         mock.Mock(side_effect=mock_logger.warning))
        self.mock_object(lib_base.LOG,
                         'error',
                         mock.Mock(side_effect=mock_logger.error))
        self.mock_object(lib_base.LOG,
                         'debug',
                         mock.Mock(side_effect=mock_logger.debug))

        kwargs = {
            'configuration': fake.get_config_cmode(),
            'private_storage': mock.Mock(),
            'app_version': fake.APP_VERSION
        }
        self.library = lib_base.NetAppCmodeFileStorageLibrary(fake.DRIVER_NAME,
                                                              **kwargs)
        self.library._client = mock.Mock()
        self.library._perf_library = mock.Mock()
        self.client = self.library._client
        self.context = mock.Mock()
        self.fake_replica = copy.deepcopy(fake.SHARE)
        self.fake_replica_2 = copy.deepcopy(fake.SHARE)
        self.fake_replica_2['id'] = fake.SHARE_ID2
        self.fake_replica_2['replica_state'] = (
            constants.REPLICA_STATE_OUT_OF_SYNC)
        self.mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=self.mock_dm_session))
        self.mock_object(data_motion, 'get_client_for_backend')

    def test_init(self):
        self.assertEqual(fake.DRIVER_NAME, self.library.driver_name)
        self.assertEqual(1, na_utils.validate_driver_instantiation.call_count)
        self.assertEqual(1, na_utils.setup_tracing.call_count)
        self.assertListEqual([], self.library._licenses)
        self.assertDictEqual({}, self.library._clients)
        self.assertDictEqual({}, self.library._ssc_stats)
        self.assertIsNotNone(self.library._app_version)

    def test_do_setup(self):
        mock_get_api_client = self.mock_object(self.library, '_get_api_client')
        self.mock_object(
            performance, 'PerformanceLibrary',
            mock.Mock(return_value='fake_perf_library'))
        self.mock_object(
            self.library._client, 'check_for_cluster_credentials',
            mock.Mock(return_value=True))
        self.library.do_setup(self.context)

        mock_get_api_client.assert_called_once_with()
        (self.library._client.check_for_cluster_credentials.
            assert_called_once_with())
        self.assertEqual('fake_perf_library', self.library._perf_library)
        self.mock_object(self.library._client,
                         'check_for_cluster_credentials',
                         mock.Mock(return_value=True))
        mock_set_cluster_info = self.mock_object(
            self.library, '_set_cluster_info')
        self.library.do_setup(self.context)
        mock_set_cluster_info.assert_called_once()

    def test_set_cluster_info(self):
        self.library._set_cluster_info()
        self.assertTrue(self.library._cluster_info['nve_support'],
                        fake.CLUSTER_NODES)

    def test_check_for_setup_error(self):

        self.library._licenses = []
        self.mock_object(self.library,
                         '_get_licenses',
                         mock.Mock(return_value=['fake_license']))
        mock_start_periodic_tasks = self.mock_object(self.library,
                                                     '_start_periodic_tasks')

        self.library.check_for_setup_error()

        self.assertEqual(['fake_license'], self.library._licenses)
        mock_start_periodic_tasks.assert_called_once_with()

    def test_get_vserver(self):
        self.assertRaises(NotImplementedError, self.library._get_vserver)

    def test_get_api_client(self):

        client_kwargs = fake.CLIENT_KWARGS.copy()

        # First call should proceed normally.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client1 = self.library._get_api_client()
        self.assertIsNotNone(client1)
        mock_client_constructor.assert_called_once_with(**client_kwargs)

        # Second call should yield the same object.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client2 = self.library._get_api_client()
        self.assertEqual(client1, client2)
        self.assertFalse(mock_client_constructor.called)

    def test_get_api_client_with_vserver(self):

        client_kwargs = fake.CLIENT_KWARGS.copy()
        client_kwargs['vserver'] = fake.VSERVER1

        # First call should proceed normally.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client1 = self.library._get_api_client(vserver=fake.VSERVER1)
        self.assertIsNotNone(client1)
        mock_client_constructor.assert_called_once_with(**client_kwargs)

        # Second call should yield the same object.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client2 = self.library._get_api_client(vserver=fake.VSERVER1)
        self.assertEqual(client1, client2)
        self.assertFalse(mock_client_constructor.called)

        # A different vserver should work normally without caching.
        mock_client_constructor = self.mock_object(client_cmode,
                                                   'NetAppCmodeClient')
        client3 = self.library._get_api_client(vserver=fake.VSERVER2)
        self.assertNotEqual(client1, client3)
        client_kwargs['vserver'] = fake.VSERVER2
        mock_client_constructor.assert_called_once_with(**client_kwargs)

    def test_get_licenses_both_protocols(self):
        self.library._have_cluster_creds = True
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=fake.LICENSES))

        result = self.library._get_licenses()

        self.assertSequenceEqual(fake.LICENSES, result)
        self.assertEqual(0, lib_base.LOG.error.call_count)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_get_licenses_one_protocol(self):
        self.library._have_cluster_creds = True
        licenses = list(fake.LICENSES)
        licenses.remove('nfs')
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=licenses))

        result = self.library._get_licenses()

        self.assertListEqual(licenses, result)
        self.assertEqual(0, lib_base.LOG.error.call_count)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_get_licenses_no_protocols(self):
        self.library._have_cluster_creds = True
        licenses = list(fake.LICENSES)
        licenses.remove('nfs')
        licenses.remove('cifs')
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=licenses))

        result = self.library._get_licenses()

        self.assertListEqual(licenses, result)
        self.assertEqual(1, lib_base.LOG.error.call_count)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_get_licenses_no_cluster_creds(self):
        self.library._have_cluster_creds = False

        result = self.library._get_licenses()

        self.assertListEqual([], result)
        self.assertEqual(1, lib_base.LOG.debug.call_count)

    def test_start_periodic_tasks(self):

        mock_update_ssc_info = self.mock_object(self.library,
                                                '_update_ssc_info')
        mock_handle_ems_logging = self.mock_object(self.library,
                                                   '_handle_ems_logging')
        mock_handle_housekeeping_tasks = self.mock_object(
            self.library, '_handle_housekeeping_tasks')
        mock_ssc_periodic_task = mock.Mock()
        mock_ems_periodic_task = mock.Mock()
        mock_housekeeping_periodic_task = mock.Mock()
        mock_loopingcall = self.mock_object(
            loopingcall,
            'FixedIntervalLoopingCall',
            mock.Mock(side_effect=[mock_ssc_periodic_task,
                                   mock_ems_periodic_task,
                                   mock_housekeeping_periodic_task]))

        self.library._start_periodic_tasks()

        self.assertTrue(mock_update_ssc_info.called)
        self.assertFalse(mock_handle_ems_logging.called)
        self.assertFalse(mock_housekeeping_periodic_task.called)
        mock_loopingcall.assert_has_calls(
            [mock.call(mock_update_ssc_info),
             mock.call(mock_handle_ems_logging),
             mock.call(mock_handle_housekeeping_tasks)])
        self.assertTrue(mock_ssc_periodic_task.start.called)
        self.assertTrue(mock_ems_periodic_task.start.called)
        self.assertTrue(mock_housekeeping_periodic_task.start.called)

    def test_get_backend_share_name(self):

        result = self.library._get_backend_share_name(fake.SHARE_ID)
        expected = (fake.VOLUME_NAME_TEMPLATE %
                    {'share_id': fake.SHARE_ID.replace('-', '_')})

        self.assertEqual(expected, result)

    def test_get_backend_snapshot_name(self):

        result = self.library._get_backend_snapshot_name(fake.SNAPSHOT_ID)
        expected = 'share_snapshot_' + fake.SNAPSHOT_ID.replace('-', '_')

        self.assertEqual(expected, result)

    def test_get_backend_cg_snapshot_name(self):

        result = self.library._get_backend_cg_snapshot_name(fake.SNAPSHOT_ID)
        expected = 'share_cg_snapshot_' + fake.SNAPSHOT_ID.replace('-', '_')

        self.assertEqual(expected, result)

    def test_get_aggregate_space_cluster_creds(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library._client,
                         'get_cluster_aggregate_capacities',
                         mock.Mock(return_value=fake.AGGREGATE_CAPACITIES))

        result = self.library._get_aggregate_space()

        (self.library._client.get_cluster_aggregate_capacities.
            assert_called_once_with(fake.AGGREGATES))
        self.assertDictEqual(fake.AGGREGATE_CAPACITIES, result)

    def test_get_aggregate_space_no_cluster_creds(self):

        self.library._have_cluster_creds = False
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library._client,
                         'get_vserver_aggregate_capacities',
                         mock.Mock(return_value=fake.AGGREGATE_CAPACITIES))

        result = self.library._get_aggregate_space()

        (self.library._client.get_vserver_aggregate_capacities.
            assert_called_once_with(fake.AGGREGATES))
        self.assertDictEqual(fake.AGGREGATE_CAPACITIES, result)

    def test_get_aggregate_node_cluster_creds(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.library._client,
                         'get_node_for_aggregate',
                         mock.Mock(return_value=fake.CLUSTER_NODE))

        result = self.library._get_aggregate_node(fake.AGGREGATE)

        (self.library._client.get_node_for_aggregate.
            assert_called_once_with(fake.AGGREGATE))
        self.assertEqual(fake.CLUSTER_NODE, result)

    def test_get_aggregate_node_no_cluster_creds(self):

        self.library._have_cluster_creds = False
        self.mock_object(self.library._client, 'get_node_for_aggregate')

        result = self.library._get_aggregate_node(fake.AGGREGATE)

        self.assertFalse(self.library._client.get_node_for_aggregate.called)
        self.assertIsNone(result)

    def test_get_default_filter_function(self):

        result = self.library.get_default_filter_function()

        self.assertEqual(self.library.DEFAULT_FILTER_FUNCTION, result)

    def test_get_default_goodness_function(self):

        result = self.library.get_default_goodness_function()

        self.assertEqual(self.library.DEFAULT_GOODNESS_FUNCTION, result)

    def test_get_share_stats(self):

        mock_get_pools = self.mock_object(
            self.library, '_get_pools',
            mock.Mock(return_value=fake.POOLS))

        result = self.library.get_share_stats(filter_function='filter',
                                              goodness_function='goodness')

        expected = {
            'share_backend_name': fake.BACKEND_NAME,
            'driver_name': fake.DRIVER_NAME,
            'vendor_name': 'NetApp',
            'driver_version': '1.0',
            'netapp_storage_family': 'ontap_cluster',
            'storage_protocol': 'NFS_CIFS',
            'pools': fake.POOLS,
            'share_group_stats': {'consistent_snapshot_support': 'host'},
        }
        self.assertDictEqual(expected, result)
        mock_get_pools.assert_called_once_with(filter_function='filter',
                                               goodness_function='goodness')

    def test_get_share_stats_with_replication(self):

        self.library.configuration.replication_domain = "fake_domain"
        mock_get_pools = self.mock_object(
            self.library, '_get_pools',
            mock.Mock(return_value=fake.POOLS))

        result = self.library.get_share_stats(filter_function='filter',
                                              goodness_function='goodness')

        expected = {
            'share_backend_name': fake.BACKEND_NAME,
            'driver_name': fake.DRIVER_NAME,
            'vendor_name': 'NetApp',
            'driver_version': '1.0',
            'netapp_storage_family': 'ontap_cluster',
            'storage_protocol': 'NFS_CIFS',
            'replication_type': 'dr',
            'replication_domain': 'fake_domain',
            'pools': fake.POOLS,
            'share_group_stats': {'consistent_snapshot_support': 'host'},
        }
        self.assertDictEqual(expected, result)
        mock_get_pools.assert_called_once_with(filter_function='filter',
                                               goodness_function='goodness')

    def test_get_share_server_pools(self):

        self.mock_object(self.library,
                         '_get_pools',
                         mock.Mock(return_value=fake.POOLS))

        result = self.library.get_share_server_pools(fake.SHARE_SERVER)

        self.assertListEqual(fake.POOLS, result)

    def test_get_pools(self):

        self.mock_object(
            self.library, '_get_aggregate_space',
            mock.Mock(return_value=fake.AGGREGATE_CAPACITIES))
        self.library._have_cluster_creds = True
        self.library._cluster_info = fake.CLUSTER_INFO
        self.library._ssc_stats = fake.SSC_INFO
        self.library._perf_library.get_node_utilization_for_pool = (
            mock.Mock(side_effect=[30.0, 42.0]))

        result = self.library._get_pools(filter_function='filter',
                                         goodness_function='goodness')

        self.assertListEqual(fake.POOLS, result)

    def test_get_pools_vserver_creds(self):

        self.mock_object(
            self.library, '_get_aggregate_space',
            mock.Mock(return_value=fake.AGGREGATE_CAPACITIES_VSERVER_CREDS))
        self.library._have_cluster_creds = False
        self.library._cluster_info = fake.CLUSTER_INFO
        self.library._ssc_stats = fake.SSC_INFO_VSERVER_CREDS
        self.library._perf_library.get_node_utilization_for_pool = (
            mock.Mock(side_effect=[50.0, 50.0]))

        result = self.library._get_pools()

        self.assertListEqual(fake.POOLS_VSERVER_CREDS, result)

    def test_handle_ems_logging(self):

        self.mock_object(self.library,
                         '_build_ems_log_message_0',
                         mock.Mock(return_value=fake.EMS_MESSAGE_0))
        self.mock_object(self.library,
                         '_build_ems_log_message_1',
                         mock.Mock(return_value=fake.EMS_MESSAGE_1))

        self.library._handle_ems_logging()

        self.library._client.send_ems_log_message.assert_has_calls([
            mock.call(fake.EMS_MESSAGE_0),
            mock.call(fake.EMS_MESSAGE_1),
        ])

    def test_build_ems_log_message_0(self):

        self.mock_object(socket,
                         'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))

        result = self.library._build_ems_log_message_0()

        self.assertDictEqual(fake.EMS_MESSAGE_0, result)

    def test_build_ems_log_message_1(self):

        pool_info = {
            'pools': {
                'vserver': 'fake_vserver',
                'aggregates': ['aggr1', 'aggr2'],
            },
        }
        self.mock_object(socket,
                         'gethostname',
                         mock.Mock(return_value=fake.HOST_NAME))
        self.mock_object(self.library,
                         '_get_ems_pool_info',
                         mock.Mock(return_value=pool_info))

        result = self.library._build_ems_log_message_1()

        self.assertDictEqual(pool_info,
                             json.loads(result['event-description']))
        result['event-description'] = ''
        self.assertDictEqual(fake.EMS_MESSAGE_1, result)

    def test_get_ems_pool_info(self):
        self.assertRaises(NotImplementedError,
                          self.library._get_ems_pool_info)

    def test_find_matching_aggregates(self):
        self.assertRaises(NotImplementedError,
                          self.library._find_matching_aggregates)

    @ddt.data(('NFS', nfs_cmode.NetAppCmodeNFSHelper),
              ('nfs', nfs_cmode.NetAppCmodeNFSHelper),
              ('CIFS', cifs_cmode.NetAppCmodeCIFSHelper),
              ('cifs', cifs_cmode.NetAppCmodeCIFSHelper))
    @ddt.unpack
    def test_get_helper(self, protocol, helper_type):

        fake_share = fake.SHARE.copy()
        fake_share['share_proto'] = protocol
        mock_check_license_for_protocol = self.mock_object(
            self.library, '_check_license_for_protocol')

        result = self.library._get_helper(fake_share)

        mock_check_license_for_protocol.assert_called_once_with(
            protocol.lower())
        self.assertEqual(helper_type, type(result))

    def test_get_helper_invalid_protocol(self):

        fake_share = fake.SHARE.copy()
        fake_share['share_proto'] = 'iSCSI'
        self.mock_object(self.library, '_check_license_for_protocol')

        self.assertRaises(exception.NetAppException,
                          self.library._get_helper,
                          fake_share)

    def test_check_license_for_protocol_no_cluster_creds(self):

        self.library._have_cluster_creds = False

        result = self.library._check_license_for_protocol('fake_protocol')

        self.assertIsNone(result)

    def test_check_license_for_protocol_have_license(self):

        self.library._have_cluster_creds = True
        self.library._licenses = ['base', 'fake_protocol']

        result = self.library._check_license_for_protocol('FAKE_PROTOCOL')

        self.assertIsNone(result)

    def test_check_license_for_protocol_newly_licensed_protocol(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_get_licenses',
                         mock.Mock(return_value=['base', 'nfs']))
        self.library._licenses = ['base']

        result = self.library._check_license_for_protocol('NFS')

        self.assertIsNone(result)
        self.assertTrue(self.library._get_licenses.called)

    def test_check_license_for_protocol_unlicensed_protocol(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_get_licenses',
                         mock.Mock(return_value=['base']))
        self.library._licenses = ['base']

        self.assertRaises(exception.NetAppException,
                          self.library._check_license_for_protocol,
                          'NFS')

    def test_get_pool_has_pool(self):
        result = self.library.get_pool(fake.SHARE)
        self.assertEqual(fake.POOL_NAME, result)
        self.assertFalse(self.client.get_aggregate_for_volume.called)

    def test_get_pool_no_pool(self):

        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['host'] = '%(host)s@%(backend)s' % {
            'host': fake.HOST_NAME, 'backend': fake.BACKEND_NAME}
        self.client.get_aggregate_for_volume.return_value = fake.POOL_NAME

        result = self.library.get_pool(fake_share)

        self.assertEqual(fake.POOL_NAME, result)
        self.assertTrue(self.client.get_aggregate_for_volume.called)

    def test_get_pool_raises(self):

        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['host'] = '%(host)s@%(backend)s' % {
            'host': fake.HOST_NAME, 'backend': fake.BACKEND_NAME}
        self.client.get_aggregate_for_volume.side_effect = (
            exception.NetAppException)

        self.assertRaises(exception.NetAppException,
                          self.library.get_pool,
                          fake_share)

    def test_create_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_allocate_container = self.mock_object(self.library,
                                                   '_allocate_container')
        mock_create_export = self.mock_object(
            self.library,
            '_create_export',
            mock.Mock(return_value='fake_export_location'))

        result = self.library.create_share(self.context,
                                           fake.SHARE,
                                           share_server=fake.SHARE_SERVER)

        mock_allocate_container.assert_called_once_with(fake.SHARE,
                                                        fake.VSERVER1,
                                                        vserver_client)
        mock_create_export.assert_called_once_with(fake.SHARE,
                                                   fake.SHARE_SERVER,
                                                   fake.VSERVER1,
                                                   vserver_client)
        self.assertEqual('fake_export_location', result)

    def test_create_share_from_snapshot(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_allocate_container_from_snapshot = self.mock_object(
            self.library,
            '_allocate_container_from_snapshot')
        mock_create_export = self.mock_object(
            self.library,
            '_create_export',
            mock.Mock(return_value='fake_export_location'))

        result = self.library.create_share_from_snapshot(
            self.context,
            fake.SHARE,
            fake.SNAPSHOT,
            share_server=fake.SHARE_SERVER)

        mock_allocate_container_from_snapshot.assert_called_once_with(
            fake.SHARE,
            fake.SNAPSHOT,
            fake.VSERVER1,
            vserver_client)
        mock_create_export.assert_called_once_with(fake.SHARE,
                                                   fake.SHARE_SERVER,
                                                   fake.VSERVER1,
                                                   vserver_client)
        self.assertEqual('fake_export_location', result)

    def test_allocate_container(self):
        self.mock_object(self.library, '_get_backend_share_name', mock.Mock(
            return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value=fake.POOL_NAME))
        mock_get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options_for_share',
            mock.Mock(return_value=copy.deepcopy(fake.PROVISIONING_OPTIONS)))
        vserver_client = mock.Mock()

        self.library._allocate_container(fake.EXTRA_SPEC_SHARE,
                                         fake.VSERVER1,
                                         vserver_client)

        mock_get_provisioning_opts.assert_called_once_with(
            fake.EXTRA_SPEC_SHARE, fake.VSERVER1, replica=False)

        vserver_client.create_volume.assert_called_once_with(
            fake.POOL_NAME, fake.SHARE_NAME, fake.SHARE['size'],
            thin_provisioned=True, snapshot_policy='default',
            language='en-US', dedup_enabled=True, split=True, encrypt=False,
            compression_enabled=False, max_files=5000, snapshot_reserve=8)

    def test_remap_standard_boolean_extra_specs(self):

        extra_specs = copy.deepcopy(fake.OVERLAPPING_EXTRA_SPEC)

        result = self.library._remap_standard_boolean_extra_specs(extra_specs)

        self.assertDictEqual(fake.REMAPPED_OVERLAPPING_EXTRA_SPEC, result)

    def test_allocate_container_as_replica(self):
        self.mock_object(self.library, '_get_backend_share_name', mock.Mock(
            return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value=fake.POOL_NAME))
        mock_get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options_for_share',
            mock.Mock(return_value=copy.deepcopy(fake.PROVISIONING_OPTIONS)))
        vserver_client = mock.Mock()

        self.library._allocate_container(fake.EXTRA_SPEC_SHARE, fake.VSERVER1,
                                         vserver_client, replica=True)

        mock_get_provisioning_opts.assert_called_once_with(
            fake.EXTRA_SPEC_SHARE, fake.VSERVER1, replica=True)

        vserver_client.create_volume.assert_called_once_with(
            fake.POOL_NAME, fake.SHARE_NAME, fake.SHARE['size'],
            thin_provisioned=True, snapshot_policy='default',
            language='en-US', dedup_enabled=True, split=True,
            compression_enabled=False, max_files=5000, encrypt=False,
            snapshot_reserve=8, volume_type='dp')

    def test_allocate_container_no_pool_name(self):
        self.mock_object(self.library, '_get_backend_share_name', mock.Mock(
            return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value=None))
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_get_provisioning_options')
        vserver_client = mock.Mock()

        self.assertRaises(exception.InvalidHost,
                          self.library._allocate_container, fake.SHARE,
                          fake.VSERVER1, vserver_client)

        self.library._get_backend_share_name.assert_called_once_with(
            fake.SHARE['id'])
        share_utils.extract_host.assert_called_once_with(fake.SHARE['host'],
                                                         level='pool')
        self.assertEqual(0,
                         self.library._check_extra_specs_validity.call_count)
        self.assertEqual(0, self.library._get_provisioning_options.call_count)

    def test_check_extra_specs_validity(self):
        boolean_extra_spec_keys = list(
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)
        mock_bool_check = self.mock_object(
            self.library, '_check_boolean_extra_specs_validity')
        mock_string_check = self.mock_object(
            self.library, '_check_string_extra_specs_validity')

        self.library._check_extra_specs_validity(
            fake.EXTRA_SPEC_SHARE, fake.EXTRA_SPEC)

        mock_bool_check.assert_called_once_with(
            fake.EXTRA_SPEC_SHARE, fake.EXTRA_SPEC, boolean_extra_spec_keys)
        mock_string_check.assert_called_once_with(
            fake.EXTRA_SPEC_SHARE, fake.EXTRA_SPEC)

    def test_check_extra_specs_validity_empty_spec(self):
        result = self.library._check_extra_specs_validity(
            fake.EXTRA_SPEC_SHARE, fake.EMPTY_EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_extra_specs_validity_invalid_value(self):
        self.assertRaises(
            exception.Invalid, self.library._check_extra_specs_validity,
            fake.EXTRA_SPEC_SHARE, fake.INVALID_EXTRA_SPEC)

    def test_check_string_extra_specs_validity(self):
        result = self.library._check_string_extra_specs_validity(
            fake.EXTRA_SPEC_SHARE, fake.EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_string_extra_specs_validity_empty_spec(self):
        result = self.library._check_string_extra_specs_validity(
            fake.EXTRA_SPEC_SHARE, fake.EMPTY_EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_string_extra_specs_validity_invalid_value(self):
        self.assertRaises(
            exception.NetAppException,
            self.library._check_string_extra_specs_validity,
            fake.EXTRA_SPEC_SHARE, fake.INVALID_MAX_FILE_EXTRA_SPEC)

    def test_check_boolean_extra_specs_validity_invalid_value(self):
        self.assertRaises(
            exception.Invalid,
            self.library._check_boolean_extra_specs_validity,
            fake.EXTRA_SPEC_SHARE, fake.INVALID_EXTRA_SPEC,
            list(self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP))

    def test_check_extra_specs_validity_invalid_combination(self):
        self.assertRaises(
            exception.Invalid,
            self.library._check_boolean_extra_specs_validity,
            fake.EXTRA_SPEC_SHARE, fake.INVALID_EXTRA_SPEC_COMBO,
            list(self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP))

    @ddt.data({'extra_specs': fake.EXTRA_SPEC, 'is_replica': False},
              {'extra_specs': fake.EXTRA_SPEC_WITH_QOS, 'is_replica': True},
              {'extra_specs': fake.EXTRA_SPEC, 'is_replica': False},
              {'extra_specs': fake.EXTRA_SPEC_WITH_QOS, 'is_replica': True})
    @ddt.unpack
    def test_get_provisioning_options_for_share(self, extra_specs, is_replica):

        qos = True if fake.QOS_EXTRA_SPEC in extra_specs else False
        mock_get_extra_specs_from_share = self.mock_object(
            share_types, 'get_extra_specs_from_share',
            mock.Mock(return_value=extra_specs))
        mock_remap_standard_boolean_extra_specs = self.mock_object(
            self.library, '_remap_standard_boolean_extra_specs',
            mock.Mock(return_value=extra_specs))
        mock_check_extra_specs_validity = self.mock_object(
            self.library, '_check_extra_specs_validity')
        mock_get_provisioning_options = self.mock_object(
            self.library, '_get_provisioning_options',
            mock.Mock(return_value=fake.PROVISIONING_OPTIONS))
        mock_get_normalized_qos_specs = self.mock_object(
            self.library, '_get_normalized_qos_specs',
            mock.Mock(return_value={fake.QOS_NORMALIZED_SPEC: 3000}))
        mock_create_qos_policy_group = self.mock_object(
            self.library, '_create_qos_policy_group', mock.Mock(
                return_value=fake.QOS_POLICY_GROUP_NAME))

        result = self.library._get_provisioning_options_for_share(
            fake.EXTRA_SPEC_SHARE, fake.VSERVER1, replica=is_replica)

        if qos and is_replica:
            expected_provisioning_opts = fake.PROVISIONING_OPTIONS
            self.assertFalse(mock_create_qos_policy_group.called)
        else:
            expected_provisioning_opts = fake.PROVISIONING_OPTIONS_WITH_QOS
            mock_create_qos_policy_group.assert_called_once_with(
                fake.EXTRA_SPEC_SHARE, fake.VSERVER1,
                {fake.QOS_NORMALIZED_SPEC: 3000})

        self.assertEqual(expected_provisioning_opts, result)
        mock_get_extra_specs_from_share.assert_called_once_with(
            fake.EXTRA_SPEC_SHARE)
        mock_remap_standard_boolean_extra_specs.assert_called_once_with(
            extra_specs)
        mock_check_extra_specs_validity.assert_called_once_with(
            fake.EXTRA_SPEC_SHARE, extra_specs)
        mock_get_provisioning_options.assert_called_once_with(extra_specs)
        mock_get_normalized_qos_specs.assert_called_once_with(extra_specs)

    def test_get_provisioning_options_implicit_false(self):
        result = self.library._get_provisioning_options(
            fake.EMPTY_EXTRA_SPEC)

        expected = {
            'language': None,
            'max_files': None,
            'snapshot_policy': None,
            'thin_provisioned': False,
            'compression_enabled': False,
            'dedup_enabled': False,
            'split': False,
            'encrypt': False,
        }

        self.assertEqual(expected, result)

    def test_get_boolean_provisioning_options(self):
        result = self.library._get_boolean_provisioning_options(
            fake.SHORT_BOOLEAN_EXTRA_SPEC,
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_BOOLEAN, result)

    def test_get_boolean_provisioning_options_missing_spec(self):
        result = self.library._get_boolean_provisioning_options(
            fake.SHORT_BOOLEAN_EXTRA_SPEC,
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_BOOLEAN, result)

    def test_get_boolean_provisioning_options_implicit_false(self):
        expected = {
            'thin_provisioned': False,
            'dedup_enabled': False,
            'compression_enabled': False,
            'split': False,
        }

        result = self.library._get_boolean_provisioning_options(
            fake.EMPTY_EXTRA_SPEC,
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(expected, result)

    def test_get_string_provisioning_options(self):
        result = self.library._get_string_provisioning_options(
            fake.STRING_EXTRA_SPEC,
            self.library.STRING_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_STRING, result)

    def test_get_string_provisioning_options_missing_spec(self):
        result = self.library._get_string_provisioning_options(
            fake.SHORT_STRING_EXTRA_SPEC,
            self.library.STRING_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_STRING_MISSING_SPECS,
                         result)

    def test_get_string_provisioning_options_implicit_false(self):
        result = self.library._get_string_provisioning_options(
            fake.EMPTY_EXTRA_SPEC,
            self.library.STRING_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_STRING_DEFAULT, result)

    @ddt.data({}, {'foo': 'bar'}, {'netapp:maxiops': '3000'},
              {'qos': True, 'netapp:absiops': '3000'},
              {'qos': True, 'netapp:maxiops:': '3000'})
    def test_get_normalized_qos_specs_no_qos_specs(self, extra_specs):
        if 'qos' in extra_specs:
            self.assertRaises(exception.NetAppException,
                              self.library._get_normalized_qos_specs,
                              extra_specs)
        else:
            self.assertDictMatch(
                {}, self.library._get_normalized_qos_specs(extra_specs))

    @ddt.data({'qos': True, 'netapp:maxiops': '3000', 'netapp:maxbps': '9000'},
              {'qos': True, 'netapp:maxiopspergib': '1000',
               'netapp:maxiops': '1000'})
    def test_get_normalized_qos_specs_multiple_qos_specs(self, extra_specs):
        self.assertRaises(exception.NetAppException,
                          self.library._get_normalized_qos_specs,
                          extra_specs)

    @ddt.data({'qos': True, 'netapp:maxIOPS': '3000'},
              {'qos': True, 'netapp:MAxBPs': '3000', 'clem': 'son'},
              {'qos': True, 'netapp:maxbps': '3000', 'tig': 'ers'},
              {'qos': True, 'netapp:MAXiopSPerGib': '3000', 'kin': 'gsof'},
              {'qos': True, 'netapp:maxiopspergib': '3000', 'coll': 'ege'},
              {'qos': True, 'netapp:maxBPSperGiB': '3000', 'foot': 'ball'})
    def test_get_normalized_qos_specs(self, extra_specs):
        expected_normalized_spec = {
            key.lower().split('netapp:')[1]: value
            for key, value in extra_specs.items() if 'netapp:' in key
        }

        qos_specs = self.library._get_normalized_qos_specs(extra_specs)

        self.assertDictMatch(expected_normalized_spec, qos_specs)
        self.assertEqual(1, len(qos_specs))

    @ddt.data({'qos': {'maxiops': '3000'}, 'expected': '3000iops'},
              {'qos': {'maxbps': '3000'}, 'expected': '3000B/s'},
              {'qos': {'maxbpspergib': '3000'}, 'expected': '12000B/s'},
              {'qos': {'maxiopspergib': '3000'}, 'expected': '12000iops'})
    @ddt.unpack
    def test_get_max_throughput(self, qos, expected):

        throughput = self.library._get_max_throughput(4, qos)

        self.assertEqual(expected, throughput)

    def test_create_qos_policy_group(self):
        mock_qos_policy_create = self.mock_object(
            self.library._client, 'qos_policy_group_create')

        self.library._create_qos_policy_group(
            fake.SHARE, fake.VSERVER1, {'maxiops': '3000'})

        expected_policy_name = 'qos_share_' + fake.SHARE['id'].replace(
            '-', '_')
        mock_qos_policy_create.assert_called_once_with(
            expected_policy_name, fake.VSERVER1, max_throughput='3000iops')

    def test_check_if_max_files_is_valid_with_negative_integer(self):
        self.assertRaises(exception.NetAppException,
                          self.library._check_if_max_files_is_valid,
                          fake.SHARE, -1)

    def test_check_if_max_files_is_valid_with_string(self):
        self.assertRaises(ValueError,
                          self.library._check_if_max_files_is_valid,
                          fake.SHARE, 'abc')

    def test_allocate_container_no_pool(self):

        vserver_client = mock.Mock()
        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['host'] = fake_share['host'].split('#')[0]

        self.assertRaises(exception.InvalidHost,
                          self.library._allocate_container,
                          fake_share,
                          fake.VSERVER1,
                          vserver_client)

    def test_check_aggregate_extra_specs_validity(self):

        self.library._have_cluster_creds = True
        self.library._ssc_stats = fake.SSC_INFO

        result = self.library._check_aggregate_extra_specs_validity(
            fake.AGGREGATES[0], fake.EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_aggregate_extra_specs_validity_no_match(self):

        self.library._have_cluster_creds = True
        self.library._ssc_stats = fake.SSC_INFO

        self.assertRaises(exception.NetAppException,
                          self.library._check_aggregate_extra_specs_validity,
                          fake.AGGREGATES[1],
                          fake.EXTRA_SPEC)

    @ddt.data({'provider_location': None, 'size': 50},
              {'provider_location': 'fake_location', 'size': 30},
              {'provider_location': 'fake_location', 'size': 20})
    @ddt.unpack
    def test_allocate_container_from_snapshot(self, provider_location, size):

        mock_get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options_for_share',
            mock.Mock(return_value=copy.deepcopy(fake.PROVISIONING_OPTIONS)))
        vserver = fake.VSERVER1
        vserver_client = mock.Mock()
        original_snapshot_size = 20

        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['size'] = size
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['provider_location'] = provider_location
        fake_snapshot['size'] = original_snapshot_size

        self.library._allocate_container_from_snapshot(fake_share,
                                                       fake_snapshot,
                                                       vserver,
                                                       vserver_client)

        share_name = self.library._get_backend_share_name(fake_share['id'])
        parent_share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        parent_snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id']) if not provider_location else 'fake_location'
        mock_get_provisioning_opts.assert_called_once_with(
            fake_share, fake.VSERVER1)
        vserver_client.create_volume_clone.assert_called_once_with(
            share_name, parent_share_name, parent_snapshot_name,
            thin_provisioned=True, snapshot_policy='default',
            language='en-US', dedup_enabled=True, split=True, encrypt=False,
            compression_enabled=False, max_files=5000)
        if size > original_snapshot_size:
            vserver_client.set_volume_size.assert_called_once_with(
                share_name, size)
        else:
            vserver_client.set_volume_size.assert_not_called()

    def test_share_exists(self):

        vserver_client = mock.Mock()
        vserver_client.volume_exists.return_value = True

        result = self.library._share_exists(fake.SHARE_NAME, vserver_client)

        self.assertTrue(result)

    def test_share_exists_not_found(self):

        vserver_client = mock.Mock()
        vserver_client.volume_exists.return_value = False

        result = self.library._share_exists(fake.SHARE_NAME, vserver_client)

        self.assertFalse(result)

    def test_delete_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=True))
        mock_remove_export = self.mock_object(self.library, '_remove_export')
        mock_deallocate_container = self.mock_object(self.library,
                                                     '_deallocate_container')

        self.library.delete_share(self.context,
                                  fake.SHARE,
                                  share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(fake.SHARE['id'])
        qos_policy_name = self.library._get_backend_qos_policy_group_name(
            fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        mock_remove_export.assert_called_once_with(fake.SHARE, vserver_client)
        mock_deallocate_container.assert_called_once_with(share_name,
                                                          vserver_client)
        (self.library._client.mark_qos_policy_group_for_deletion
         .assert_called_once_with(qos_policy_name))
        self.assertEqual(0, lib_base.LOG.info.call_count)

    @ddt.data(exception.InvalidInput(reason='fake_reason'),
              exception.VserverNotSpecified(),
              exception.VserverNotFound(vserver='fake_vserver'))
    def test_delete_share_no_share_server(self, get_vserver_exception):

        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(side_effect=get_vserver_exception))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=False))
        mock_remove_export = self.mock_object(self.library, '_remove_export')
        mock_deallocate_container = self.mock_object(self.library,
                                                     '_deallocate_container')

        self.library.delete_share(self.context,
                                  fake.SHARE,
                                  share_server=fake.SHARE_SERVER)

        self.assertFalse(mock_share_exists.called)
        self.assertFalse(mock_remove_export.called)
        self.assertFalse(mock_deallocate_container.called)
        self.assertFalse(
            self.library._client.mark_qos_policy_group_for_deletion.called)
        self.assertEqual(1, lib_base.LOG.warning.call_count)

    def test_delete_share_not_found(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=False))
        mock_remove_export = self.mock_object(self.library, '_remove_export')
        mock_deallocate_container = self.mock_object(self.library,
                                                     '_deallocate_container')

        self.library.delete_share(self.context,
                                  fake.SHARE,
                                  share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        self.assertFalse(mock_remove_export.called)
        self.assertFalse(mock_deallocate_container.called)
        self.assertFalse(
            self.library._client.mark_qos_policy_group_for_deletion.called)
        self.assertEqual(1, lib_base.LOG.info.call_count)

    def test_deallocate_container(self):

        vserver_client = mock.Mock()

        self.library._deallocate_container(fake.SHARE_NAME, vserver_client)

        vserver_client.unmount_volume.assert_called_with(fake.SHARE_NAME,
                                                         force=True)
        vserver_client.offline_volume.assert_called_with(fake.SHARE_NAME)
        vserver_client.delete_volume.assert_called_with(fake.SHARE_NAME)

    def test_create_export(self):

        protocol_helper = mock.Mock()
        callback = (lambda export_address, export_path='fake_export_path':
                    ':'.join([export_address, export_path]))
        protocol_helper.create_share.return_value = callback
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()
        vserver_client.get_network_interfaces.return_value = fake.LIFS
        fake_interface_addresses_with_metadata = copy.deepcopy(
            fake.INTERFACE_ADDRESSES_WITH_METADATA)
        mock_get_export_addresses_with_metadata = self.mock_object(
            self.library, '_get_export_addresses_with_metadata',
            mock.Mock(return_value=fake_interface_addresses_with_metadata))

        result = self.library._create_export(fake.SHARE,
                                             fake.SHARE_SERVER,
                                             fake.VSERVER1,
                                             vserver_client)

        self.assertEqual(fake.NFS_EXPORTS, result)
        mock_get_export_addresses_with_metadata.assert_called_once_with(
            fake.SHARE, fake.SHARE_SERVER, fake.LIFS)
        protocol_helper.create_share.assert_called_once_with(
            fake.SHARE, fake.SHARE_NAME, clear_current_export_policy=True)

    def test_create_export_lifs_not_found(self):

        self.mock_object(self.library, '_get_helper')
        vserver_client = mock.Mock()
        vserver_client.get_network_interfaces.return_value = []

        self.assertRaises(exception.NetAppException,
                          self.library._create_export,
                          fake.SHARE,
                          fake.SHARE_SERVER,
                          fake.VSERVER1,
                          vserver_client)

    def test_get_export_addresses_with_metadata(self):

        mock_get_aggregate_node = self.mock_object(
            self.library, '_get_aggregate_node',
            mock.Mock(return_value=fake.CLUSTER_NODES[0]))
        mock_get_admin_addresses_for_share_server = self.mock_object(
            self.library, '_get_admin_addresses_for_share_server',
            mock.Mock(return_value=[fake.LIF_ADDRESSES[1]]))

        result = self.library._get_export_addresses_with_metadata(
            fake.SHARE, fake.SHARE_SERVER, fake.LIFS)

        self.assertEqual(fake.INTERFACE_ADDRESSES_WITH_METADATA, result)
        mock_get_aggregate_node.assert_called_once_with(fake.POOL_NAME)
        mock_get_admin_addresses_for_share_server.assert_called_once_with(
            fake.SHARE_SERVER)

    def test_get_export_addresses_with_metadata_node_unknown(self):

        mock_get_aggregate_node = self.mock_object(
            self.library, '_get_aggregate_node',
            mock.Mock(return_value=None))
        mock_get_admin_addresses_for_share_server = self.mock_object(
            self.library, '_get_admin_addresses_for_share_server',
            mock.Mock(return_value=[fake.LIF_ADDRESSES[1]]))

        result = self.library._get_export_addresses_with_metadata(
            fake.SHARE, fake.SHARE_SERVER, fake.LIFS)

        expected = copy.deepcopy(fake.INTERFACE_ADDRESSES_WITH_METADATA)
        for key, value in expected.items():
            value['preferred'] = False

        self.assertEqual(expected, result)
        mock_get_aggregate_node.assert_called_once_with(fake.POOL_NAME)
        mock_get_admin_addresses_for_share_server.assert_called_once_with(
            fake.SHARE_SERVER)

    def test_get_admin_addresses_for_share_server(self):

        result = self.library._get_admin_addresses_for_share_server(
            fake.SHARE_SERVER)

        self.assertEqual([fake.ADMIN_NETWORK_ALLOCATIONS[0]['ip_address']],
                         result)

    def test_get_admin_addresses_for_share_server_no_share_server(self):

        result = self.library._get_admin_addresses_for_share_server(None)

        self.assertEqual([], result)

    @ddt.data(True, False)
    def test_sort_export_locations_by_preferred_paths(self, reverse):

        export_locations = copy.copy(fake.NFS_EXPORTS)
        if reverse:
            export_locations.reverse()

        result = self.library._sort_export_locations_by_preferred_paths(
            export_locations)

        self.assertEqual(fake.NFS_EXPORTS, result)

    def test_remove_export(self):

        protocol_helper = mock.Mock()
        protocol_helper.get_target.return_value = 'fake_target'
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()

        self.library._remove_export(fake.SHARE, vserver_client)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.get_target.assert_called_once_with(fake.SHARE)
        protocol_helper.delete_share.assert_called_once_with(fake.SHARE,
                                                             fake.SHARE_NAME)

    def test_remove_export_target_not_found(self):

        protocol_helper = mock.Mock()
        protocol_helper.get_target.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        vserver_client = mock.Mock()

        self.library._remove_export(fake.SHARE, vserver_client)

        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.get_target.assert_called_once_with(fake.SHARE)
        self.assertFalse(protocol_helper.delete_share.called)

    def test_create_snapshot(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        model_update = self.library.create_snapshot(
            self.context, fake.SNAPSHOT, share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(
            fake.SNAPSHOT['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake.SNAPSHOT['id'])
        vserver_client.create_snapshot.assert_called_once_with(share_name,
                                                               snapshot_name)
        self.assertEqual(snapshot_name, model_update['provider_location'])

    @ddt.data(True, False)
    def test_revert_to_snapshot(self, use_snap_provider_location):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        if use_snap_provider_location:
            fake_snapshot['provider_location'] = 'fake-provider-location'
        else:
            del fake_snapshot['provider_location']

        result = self.library.revert_to_snapshot(
            self.context, fake_snapshot, share_server=fake.SHARE_SERVER)

        self.assertIsNone(result)
        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = (self.library._get_backend_snapshot_name(
            fake_snapshot['id']) if not use_snap_provider_location
            else 'fake-provider-location')
        vserver_client.restore_snapshot.assert_called_once_with(share_name,
                                                                snapshot_name)

    def test_delete_snapshot(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_delete_snapshot = self.mock_object(self.library,
                                                '_delete_snapshot')

        self.library.delete_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(
            fake.SNAPSHOT['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake.SNAPSHOT['id'])
        mock_delete_snapshot.assert_called_once_with(
            vserver_client, share_name, snapshot_name)

    def test_delete_snapshot_with_provider_location(self):
        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['provider_location'] = 'fake_provider_location'

        self.library.delete_snapshot(self.context,
                                     fake_snapshot,
                                     share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        vserver_client.delete_snapshot.assert_called_once_with(
            share_name,  fake_snapshot['provider_location'])

    @ddt.data(exception.InvalidInput(reason='fake_reason'),
              exception.VserverNotSpecified(),
              exception.VserverNotFound(vserver='fake_vserver'))
    def test_delete_snapshot_no_share_server(self, get_vserver_exception):

        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(side_effect=get_vserver_exception))
        mock_delete_snapshot = self.mock_object(self.library,
                                                '_delete_snapshot')

        self.library.delete_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        self.assertFalse(mock_delete_snapshot.called)

    def test_delete_snapshot_not_found(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_delete_snapshot = self.mock_object(
            self.library, '_delete_snapshot',
            mock.Mock(side_effect=exception.SnapshotResourceNotFound(
                name=fake.SNAPSHOT_NAME)))

        self.library.delete_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(
            fake.SNAPSHOT['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake.SNAPSHOT['id'])
        mock_delete_snapshot.assert_called_once_with(
            vserver_client, share_name, snapshot_name)

    def test_delete_snapshot_not_unique(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_delete_snapshot = self.mock_object(
            self.library, '_delete_snapshot',
            mock.Mock(side_effect=exception.NetAppException()))

        self.assertRaises(exception.NetAppException,
                          self.library.delete_snapshot,
                          self.context,
                          fake.SNAPSHOT,
                          share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(
            fake.SNAPSHOT['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake.SNAPSHOT['id'])
        mock_delete_snapshot.assert_called_once_with(
            vserver_client, share_name, snapshot_name)

    def test__delete_snapshot(self):

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT

        self.library._delete_snapshot(vserver_client,
                                      fake.SHARE_NAME,
                                      fake.SNAPSHOT_NAME)

        vserver_client.delete_snapshot.assert_called_once_with(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)
        self.assertFalse(vserver_client.get_clone_children_for_snapshot.called)
        self.assertFalse(vserver_client.split_volume_clone.called)
        self.assertFalse(vserver_client.soft_delete_snapshot.called)

    def test__delete_snapshot_busy_volume_clone(self):

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = (
            fake.CDOT_SNAPSHOT_BUSY_VOLUME_CLONE)
        vserver_client.get_clone_children_for_snapshot.return_value = (
            fake.CDOT_CLONE_CHILDREN)

        self.library._delete_snapshot(vserver_client,
                                      fake.SHARE_NAME,
                                      fake.SNAPSHOT_NAME)

        self.assertFalse(vserver_client.delete_snapshot.called)
        vserver_client.get_clone_children_for_snapshot.assert_called_once_with(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)
        vserver_client.split_volume_clone.assert_has_calls([
            mock.call(fake.CDOT_CLONE_CHILD_1),
            mock.call(fake.CDOT_CLONE_CHILD_2),
        ])
        vserver_client.soft_delete_snapshot.assert_called_once_with(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)

    def test__delete_snapshot_busy_snapmirror(self):

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = (
            fake.CDOT_SNAPSHOT_BUSY_SNAPMIRROR)

        self.assertRaises(exception.ShareSnapshotIsBusy,
                          self.library._delete_snapshot,
                          vserver_client,
                          fake.SHARE_NAME,
                          fake.SNAPSHOT_NAME)

        self.assertFalse(vserver_client.delete_snapshot.called)
        self.assertFalse(vserver_client.get_clone_children_for_snapshot.called)
        self.assertFalse(vserver_client.split_volume_clone.called)
        self.assertFalse(vserver_client.soft_delete_snapshot.called)

    def test_manage_existing(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_manage_container = self.mock_object(
            self.library,
            '_manage_container',
            mock.Mock(return_value=fake.SHARE_SIZE))
        mock_create_export = self.mock_object(
            self.library,
            '_create_export',
            mock.Mock(return_value=fake.NFS_EXPORTS))

        result = self.library.manage_existing(fake.SHARE, {})

        expected = {
            'size': fake.SHARE_SIZE,
            'export_locations': fake.NFS_EXPORTS
        }
        mock_manage_container.assert_called_once_with(fake.SHARE,
                                                      fake.VSERVER1,
                                                      vserver_client)
        mock_create_export.assert_called_once_with(fake.SHARE,
                                                   None,
                                                   fake.VSERVER1,
                                                   vserver_client)
        self.assertDictEqual(expected, result)

    def test_unmanage(self):

        result = self.library.unmanage(fake.SHARE)

        self.assertIsNone(result)

    @ddt.data(True, False)
    def test_manage_container_with_qos(self, qos):

        vserver_client = mock.Mock()
        qos_policy_group_name = fake.QOS_POLICY_GROUP_NAME if qos else None
        extra_specs = fake.EXTRA_SPEC_WITH_QOS if qos else fake.EXTRA_SPEC
        provisioning_opts = self.library._get_provisioning_options(extra_specs)
        if qos:
            provisioning_opts['qos_policy_group'] = fake.QOS_POLICY_GROUP_NAME

        share_to_manage = copy.deepcopy(fake.SHARE)
        share_to_manage['export_location'] = fake.EXPORT_LOCATION

        mock_helper = mock.Mock()
        mock_helper.get_share_name_for_share.return_value = fake.FLEXVOL_NAME
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock_helper))

        mock_get_volume_to_manage = self.mock_object(
            vserver_client,
            'get_volume_to_manage',
            mock.Mock(return_value=fake.FLEXVOL_TO_MANAGE))
        mock_validate_volume_for_manage = self.mock_object(
            self.library,
            '_validate_volume_for_manage')
        self.mock_object(share_types,
                         'get_extra_specs_from_share',
                         mock.Mock(return_value=extra_specs))
        mock_check_extra_specs_validity = self.mock_object(
            self.library,
            '_check_extra_specs_validity')
        mock_check_aggregate_extra_specs_validity = self.mock_object(
            self.library,
            '_check_aggregate_extra_specs_validity')
        mock_modify_or_create_qos_policy = self.mock_object(
            self.library, '_modify_or_create_qos_for_existing_share',
            mock.Mock(return_value=qos_policy_group_name))

        result = self.library._manage_container(share_to_manage,
                                                fake.VSERVER1,
                                                vserver_client)

        mock_get_volume_to_manage.assert_called_once_with(
            fake.POOL_NAME, fake.FLEXVOL_NAME)
        mock_check_extra_specs_validity.assert_called_once_with(
            share_to_manage, extra_specs)
        mock_check_aggregate_extra_specs_validity.assert_called_once_with(
            fake.POOL_NAME, extra_specs)
        vserver_client.unmount_volume.assert_called_once_with(
            fake.FLEXVOL_NAME)
        vserver_client.set_volume_name.assert_called_once_with(
            fake.FLEXVOL_NAME, fake.SHARE_NAME)
        vserver_client.mount_volume.assert_called_once_with(
            fake.SHARE_NAME)
        vserver_client.modify_volume.assert_called_once_with(
            fake.POOL_NAME, fake.SHARE_NAME, **provisioning_opts)
        mock_modify_or_create_qos_policy.assert_called_once_with(
            share_to_manage, extra_specs, fake.VSERVER1, vserver_client)
        mock_validate_volume_for_manage.assert_called()

        original_data = {
            'original_name': fake.FLEXVOL_TO_MANAGE['name'],
            'original_junction_path': fake.FLEXVOL_TO_MANAGE['junction-path'],
        }
        self.library.private_storage.update.assert_called_once_with(
            fake.SHARE['id'], original_data)

        expected_size = int(
            math.ceil(float(fake.FLEXVOL_TO_MANAGE['size']) / units.Gi))
        self.assertEqual(expected_size, result)

    def test_manage_container_invalid_export_location(self):

        vserver_client = mock.Mock()

        share_to_manage = copy.deepcopy(fake.SHARE)
        share_to_manage['export_location'] = fake.EXPORT_LOCATION

        mock_helper = mock.Mock()
        mock_helper.get_share_name_for_share.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock_helper))

        self.assertRaises(exception.ManageInvalidShare,
                          self.library._manage_container,
                          share_to_manage,
                          fake.VSERVER1,
                          vserver_client)

    def test_manage_container_not_found(self):

        vserver_client = mock.Mock()

        share_to_manage = copy.deepcopy(fake.SHARE)
        share_to_manage['export_location'] = fake.EXPORT_LOCATION

        mock_helper = mock.Mock()
        mock_helper.get_share_name_for_share.return_value = fake.FLEXVOL_NAME
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock_helper))

        self.mock_object(vserver_client,
                         'get_volume_to_manage',
                         mock.Mock(return_value=None))

        self.assertRaises(exception.ManageInvalidShare,
                          self.library._manage_container,
                          share_to_manage,
                          fake.VSERVER1,
                          vserver_client)

    def test_manage_container_invalid_extra_specs(self):

        vserver_client = mock.Mock()

        share_to_manage = copy.deepcopy(fake.SHARE)
        share_to_manage['export_location'] = fake.EXPORT_LOCATION

        mock_helper = mock.Mock()
        mock_helper.get_share_name_for_share.return_value = fake.FLEXVOL_NAME
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock_helper))

        self.mock_object(vserver_client,
                         'get_volume_to_manage',
                         mock.Mock(return_value=fake.FLEXVOL_TO_MANAGE))
        self.mock_object(self.library, '_validate_volume_for_manage')
        self.mock_object(share_types,
                         'get_extra_specs_from_share',
                         mock.Mock(return_value=fake.EXTRA_SPEC))
        self.mock_object(self.library,
                         '_check_extra_specs_validity',
                         mock.Mock(side_effect=exception.NetAppException))

        self.assertRaises(exception.ManageExistingShareTypeMismatch,
                          self.library._manage_container,
                          share_to_manage,
                          fake.VSERVER1,
                          vserver_client)

    def test_validate_volume_for_manage(self):

        vserver_client = mock.Mock()
        vserver_client.volume_has_luns = mock.Mock(return_value=False)
        vserver_client.volume_has_junctioned_volumes = mock.Mock(
            return_value=False)
        vserver_client.volume_has_snapmirror_relationships = mock.Mock(
            return_value=False)

        result = self.library._validate_volume_for_manage(
            fake.FLEXVOL_TO_MANAGE, vserver_client)

        self.assertIsNone(result)

    @ddt.data({
        'attribute': 'type',
        'value': 'dp',
    }, {
        'attribute': 'style',
        'value': 'infinitevol',
    })
    @ddt.unpack
    def test_validate_volume_for_manage_invalid_volume(self, attribute, value):

        flexvol_to_manage = copy.deepcopy(fake.FLEXVOL_TO_MANAGE)
        flexvol_to_manage[attribute] = value

        vserver_client = mock.Mock()
        vserver_client.volume_has_luns = mock.Mock(return_value=False)
        vserver_client.volume_has_junctioned_volumes = mock.Mock(
            return_value=False)
        vserver_client.volume_has_snapmirror_relationships = mock.Mock(
            return_value=False)

        self.assertRaises(exception.ManageInvalidShare,
                          self.library._validate_volume_for_manage,
                          flexvol_to_manage,
                          vserver_client)

    def test_validate_volume_for_manage_luns_present(self):

        vserver_client = mock.Mock()
        vserver_client.volume_has_luns = mock.Mock(return_value=True)
        vserver_client.volume_has_junctioned_volumes = mock.Mock(
            return_value=False)
        vserver_client.volume_has_snapmirror_relationships = mock.Mock(
            return_value=False)

        self.assertRaises(exception.ManageInvalidShare,
                          self.library._validate_volume_for_manage,
                          fake.FLEXVOL_TO_MANAGE,
                          vserver_client)

    def test_validate_volume_for_manage_junctioned_volumes_present(self):

        vserver_client = mock.Mock()
        vserver_client.volume_has_luns = mock.Mock(return_value=False)
        vserver_client.volume_has_junctioned_volumes = mock.Mock(
            return_value=True)
        vserver_client.volume_has_snapmirror_relationships = mock.Mock(
            return_value=False)

        self.assertRaises(exception.ManageInvalidShare,
                          self.library._validate_volume_for_manage,
                          fake.FLEXVOL_TO_MANAGE,
                          vserver_client)

    def test_manage_existing_snapshot(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        vserver_client.get_volume.return_value = fake.FLEXVOL_TO_MANAGE
        vserver_client.volume_has_snapmirror_relationships.return_value = False
        result = self.library.manage_existing_snapshot(
            fake.SNAPSHOT_TO_MANAGE, {})

        share_name = self.library._get_backend_share_name(
            fake.SNAPSHOT['share_id'])
        new_snapshot_name = self.library._get_backend_snapshot_name(
            fake.SNAPSHOT['id'])
        mock_get_vserver.assert_called_once_with(share_server=None)
        (vserver_client.volume_has_snapmirror_relationships.
            assert_called_once_with(fake.FLEXVOL_TO_MANAGE))
        vserver_client.rename_snapshot.assert_called_once_with(
            share_name, fake.SNAPSHOT_NAME, new_snapshot_name)
        self.library.private_storage.update.assert_called_once_with(
            fake.SNAPSHOT['id'], {'original_name': fake.SNAPSHOT_NAME})
        self.assertEqual({'size': 2, 'provider_location': new_snapshot_name},
                         result)

    def test_manage_existing_snapshot_no_snapshot_name(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        vserver_client.get_volume.return_value = fake.FLEXVOL_TO_MANAGE
        vserver_client.volume_has_snapmirror_relationships.return_value = False
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT_TO_MANAGE)
        fake_snapshot['provider_location'] = ''

        self.assertRaises(exception.ManageInvalidShareSnapshot,
                          self.library.manage_existing_snapshot,
                          fake_snapshot, {})

    @ddt.data(netapp_api.NaApiError,
              exception.NetAppException)
    def test_manage_existing_snapshot_get_volume_error(self, exception_type):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        vserver_client.get_volume.side_effect = exception_type
        self.mock_object(self.client,
                         'volume_has_snapmirror_relationships',
                         mock.Mock(return_value=False))

        self.assertRaises(exception.ShareNotFound,
                          self.library.manage_existing_snapshot,
                          fake.SNAPSHOT_TO_MANAGE, {})

    def test_manage_existing_snapshot_mirrors_present(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        vserver_client.get_volume.return_value = fake.FLEXVOL_TO_MANAGE
        vserver_client.volume_has_snapmirror_relationships.return_value = True

        self.assertRaises(exception.ManageInvalidShareSnapshot,
                          self.library.manage_existing_snapshot,
                          fake.SNAPSHOT_TO_MANAGE, {})

    def test_manage_existing_snapshot_rename_snapshot_error(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        vserver_client.get_volume.return_value = fake.FLEXVOL_TO_MANAGE
        vserver_client.volume_has_snapmirror_relationships.return_value = False
        vserver_client.rename_snapshot.side_effect = netapp_api.NaApiError

        self.assertRaises(exception.ManageInvalidShareSnapshot,
                          self.library.manage_existing_snapshot,
                          fake.SNAPSHOT_TO_MANAGE, {})

    def test_unmanage_snapshot(self):

        result = self.library.unmanage_snapshot(fake.SNAPSHOT)

        self.assertIsNone(result)

    def test_validate_volume_for_manage_snapmirror_relationships_present(self):

        vserver_client = mock.Mock()
        vserver_client.volume_has_luns.return_value = False
        vserver_client.volume_has_junctioned_volumes.return_value = False
        vserver_client.volume_has_snapmirror_relationships.return_value = True

        self.assertRaises(exception.ManageInvalidShare,
                          self.library._validate_volume_for_manage,
                          fake.FLEXVOL_TO_MANAGE,
                          vserver_client)

    def test_create_consistency_group_from_cgsnapshot(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        mock_allocate_container_from_snapshot = self.mock_object(
            self.library, '_allocate_container_from_snapshot')
        mock_create_export = self.mock_object(
            self.library, '_create_export',
            mock.Mock(side_effect=[['loc3'], ['loc4']]))

        result = self.library.create_consistency_group_from_cgsnapshot(
            self.context,
            fake.CONSISTENCY_GROUP_DEST,
            fake.CG_SNAPSHOT,
            share_server=fake.SHARE_SERVER)

        share_update_list = [
            {'id': fake.SHARE_ID3, 'export_locations': ['loc3']},
            {'id': fake.SHARE_ID4, 'export_locations': ['loc4']}
        ]
        expected = (None, share_update_list)
        self.assertEqual(expected, result)

        mock_allocate_container_from_snapshot.assert_has_calls([
            mock.call(fake.COLLATED_CGSNAPSHOT_INFO[0]['share'],
                      fake.COLLATED_CGSNAPSHOT_INFO[0]['snapshot'],
                      fake.VSERVER1,
                      vserver_client,
                      mock.ANY),
            mock.call(fake.COLLATED_CGSNAPSHOT_INFO[1]['share'],
                      fake.COLLATED_CGSNAPSHOT_INFO[1]['snapshot'],
                      fake.VSERVER1,
                      vserver_client,
                      mock.ANY),
        ])
        mock_create_export.assert_has_calls([
            mock.call(fake.COLLATED_CGSNAPSHOT_INFO[0]['share'],
                      fake.SHARE_SERVER,
                      fake.VSERVER1,
                      vserver_client),
            mock.call(fake.COLLATED_CGSNAPSHOT_INFO[1]['share'],
                      fake.SHARE_SERVER,
                      fake.VSERVER1,
                      vserver_client),
        ])
        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)

    def test_create_consistency_group_from_cgsnapshot_no_members(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        mock_allocate_container_from_snapshot = self.mock_object(
            self.library, '_allocate_container_from_snapshot')
        mock_create_export = self.mock_object(
            self.library, '_create_export',
            mock.Mock(side_effect=[['loc3'], ['loc4']]))

        fake_cg_snapshot = copy.deepcopy(fake.CG_SNAPSHOT)
        fake_cg_snapshot['share_group_snapshot_members'] = []

        result = self.library.create_consistency_group_from_cgsnapshot(
            self.context,
            fake.CONSISTENCY_GROUP_DEST,
            fake_cg_snapshot,
            share_server=fake.SHARE_SERVER)

        self.assertEqual((None, None), result)

        self.assertFalse(mock_allocate_container_from_snapshot.called)
        self.assertFalse(mock_create_export.called)
        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)

    def test_collate_cg_snapshot_info(self):

        result = self.library._collate_cg_snapshot_info(
            fake.CONSISTENCY_GROUP_DEST, fake.CG_SNAPSHOT)

        self.assertEqual(fake.COLLATED_CGSNAPSHOT_INFO, result)

    def test_collate_cg_snapshot_info_invalid(self):

        fake_cg_snapshot = copy.deepcopy(fake.CG_SNAPSHOT)
        fake_cg_snapshot['share_group_snapshot_members'] = []

        self.assertRaises(exception.InvalidShareGroup,
                          self.library._collate_cg_snapshot_info,
                          fake.CONSISTENCY_GROUP_DEST, fake_cg_snapshot)

    def test_create_cgsnapshot(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))

        result = self.library.create_cgsnapshot(
            self.context,
            fake.CG_SNAPSHOT,
            share_server=fake.SHARE_SERVER)

        share_names = [
            self.library._get_backend_share_name(
                fake.CG_SNAPSHOT_MEMBER_1['share_id']),
            self.library._get_backend_share_name(
                fake.CG_SNAPSHOT_MEMBER_2['share_id'])
        ]
        snapshot_name = self.library._get_backend_cg_snapshot_name(
            fake.CG_SNAPSHOT['id'])
        vserver_client.create_cg_snapshot.assert_called_once_with(
            share_names, snapshot_name)
        self.assertEqual((None, None), result)
        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)

    def test_create_cgsnapshot_no_members(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))

        fake_cg_snapshot = copy.deepcopy(fake.CG_SNAPSHOT)
        fake_cg_snapshot['share_group_snapshot_members'] = []

        result = self.library.create_cgsnapshot(
            self.context,
            fake_cg_snapshot,
            share_server=fake.SHARE_SERVER)

        self.assertFalse(vserver_client.create_cg_snapshot.called)
        self.assertEqual((None, None), result)
        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)

    def test_delete_cgsnapshot(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        mock_delete_snapshot = self.mock_object(self.library,
                                                '_delete_snapshot')

        result = self.library.delete_cgsnapshot(
            self.context,
            fake.CG_SNAPSHOT,
            share_server=fake.SHARE_SERVER)

        share_names = [
            self.library._get_backend_share_name(
                fake.CG_SNAPSHOT_MEMBER_1['share_id']),
            self.library._get_backend_share_name(
                fake.CG_SNAPSHOT_MEMBER_2['share_id'])
        ]
        snapshot_name = self.library._get_backend_cg_snapshot_name(
            fake.CG_SNAPSHOT['id'])

        mock_delete_snapshot.assert_has_calls([
            mock.call(vserver_client, share_names[0], snapshot_name),
            mock.call(vserver_client, share_names[1], snapshot_name)
        ])
        self.assertEqual((None, None), result)
        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)

    def test_delete_cgsnapshot_no_members(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        mock_delete_snapshot = self.mock_object(self.library,
                                                '_delete_snapshot')

        fake_cg_snapshot = copy.deepcopy(fake.CG_SNAPSHOT)
        fake_cg_snapshot['share_group_snapshot_members'] = []

        result = self.library.delete_cgsnapshot(
            self.context,
            fake_cg_snapshot,
            share_server=fake.SHARE_SERVER)

        self.assertFalse(mock_delete_snapshot.called)
        self.assertEqual((None, None), result)
        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)

    def test_delete_cgsnapshot_snapshots_not_found(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        mock_delete_snapshot = self.mock_object(
            self.library, '_delete_snapshot',
            mock.Mock(side_effect=exception.SnapshotResourceNotFound(
                name='fake')))

        result = self.library.delete_cgsnapshot(
            self.context,
            fake.CG_SNAPSHOT,
            share_server=fake.SHARE_SERVER)

        share_names = [
            self.library._get_backend_share_name(
                fake.CG_SNAPSHOT_MEMBER_1['share_id']),
            self.library._get_backend_share_name(
                fake.CG_SNAPSHOT_MEMBER_2['share_id'])
        ]
        snapshot_name = self.library._get_backend_cg_snapshot_name(
            fake.CG_SNAPSHOT['id'])

        mock_delete_snapshot.assert_has_calls([
            mock.call(vserver_client, share_names[0], snapshot_name),
            mock.call(vserver_client, share_names[1], snapshot_name)
        ])
        self.assertEqual((None, None), result)
        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)

    @ddt.data(exception.InvalidInput(reason='fake_reason'),
              exception.VserverNotSpecified(),
              exception.VserverNotFound(vserver='fake_vserver'))
    def test_delete_cgsnapshot_no_share_server(self,
                                               get_vserver_exception):

        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(side_effect=get_vserver_exception))

        result = self.library.delete_cgsnapshot(
            self.context,
            fake.EMPTY_CONSISTENCY_GROUP,
            share_server=fake.SHARE_SERVER)

        self.assertEqual((None, None), result)
        self.assertEqual(1, lib_base.LOG.warning.call_count)
        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)

    def test_adjust_qos_policy_with_volume_resize_no_cluster_creds(self):
        self.library._have_cluster_creds = False
        self.mock_object(share_types, 'get_extra_specs_from_share')

        retval = self.library._adjust_qos_policy_with_volume_resize(
            fake.SHARE, 10, mock.Mock())

        self.assertIsNone(retval)
        share_types.get_extra_specs_from_share.assert_not_called()

    def test_adjust_qos_policy_with_volume_resize_no_qos_on_share(self):
        self.library._have_cluster_creds = True
        self.mock_object(share_types, 'get_extra_specs_from_share')
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'get_volume',
                         mock.Mock(return_value=fake.FLEXVOL_WITHOUT_QOS))

        retval = self.library._adjust_qos_policy_with_volume_resize(
            fake.SHARE, 10, vserver_client)

        self.assertIsNone(retval)
        share_types.get_extra_specs_from_share.assert_not_called()

    def test_adjust_qos_policy_with_volume_resize_no_size_dependent_qos(self):
        self.library._have_cluster_creds = True
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=fake.EXTRA_SPEC_WITH_QOS))
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'get_volume',
                         mock.Mock(return_value=fake.FLEXVOL_WITH_QOS))
        self.mock_object(self.library, '_get_max_throughput')
        self.mock_object(self.library._client, 'qos_policy_group_modify')

        retval = self.library._adjust_qos_policy_with_volume_resize(
            fake.SHARE, 10, vserver_client)

        self.assertIsNone(retval)
        share_types.get_extra_specs_from_share.assert_called_once_with(
            fake.SHARE)
        self.library._get_max_throughput.assert_not_called()
        self.library._client.qos_policy_group_modify.assert_not_called()

    def test_adjust_qos_policy_with_volume_resize(self):
        self.library._have_cluster_creds = True
        self.mock_object(
            share_types, 'get_extra_specs_from_share',
            mock.Mock(return_value=fake.EXTRA_SPEC_WITH_SIZE_DEPENDENT_QOS))
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'get_volume',
                         mock.Mock(return_value=fake.FLEXVOL_WITH_QOS))
        self.mock_object(self.library._client, 'qos_policy_group_modify')

        retval = self.library._adjust_qos_policy_with_volume_resize(
            fake.SHARE, 10, vserver_client)

        expected_max_throughput = '10000B/s'
        self.assertIsNone(retval)
        share_types.get_extra_specs_from_share.assert_called_once_with(
            fake.SHARE)
        self.library._client.qos_policy_group_modify.assert_called_once_with(
            fake.QOS_POLICY_GROUP_NAME, expected_max_throughput)

    def test_extend_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_adjust_qos_policy = self.mock_object(
            self.library, '_adjust_qos_policy_with_volume_resize')

        mock_set_volume_size = self.mock_object(vserver_client,
                                                'set_volume_size')
        new_size = fake.SHARE['size'] * 2

        self.library.extend_share(fake.SHARE, new_size)

        mock_set_volume_size.assert_called_once_with(fake.SHARE_NAME, new_size)
        mock_adjust_qos_policy.assert_called_once_with(
            fake.SHARE, new_size, vserver_client)

    def test_shrink_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_adjust_qos_policy = self.mock_object(
            self.library, '_adjust_qos_policy_with_volume_resize')
        mock_set_volume_size = self.mock_object(vserver_client,
                                                'set_volume_size')
        new_size = fake.SHARE['size'] - 1

        self.library.shrink_share(fake.SHARE, new_size)

        mock_set_volume_size.assert_called_once_with(fake.SHARE_NAME, new_size)
        mock_adjust_qos_policy.assert_called_once_with(
            fake.SHARE, new_size, vserver_client)

    def test_update_access(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        protocol_helper = mock.Mock()
        protocol_helper.update_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=True))

        self.library.update_access(self.context,
                                   fake.SHARE,
                                   [fake.SHARE_ACCESS],
                                   [],
                                   [],
                                   share_server=fake.SHARE_SERVER)

        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)
        share_name = self.library._get_backend_share_name(fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.update_access.assert_called_once_with(
            fake.SHARE, fake.SHARE_NAME, [fake.SHARE_ACCESS])

    @ddt.data(exception.InvalidInput(reason='fake_reason'),
              exception.VserverNotSpecified(),
              exception.VserverNotFound(vserver='fake_vserver'))
    def test_update_access_no_share_server(self, get_vserver_exception):

        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(side_effect=get_vserver_exception))
        protocol_helper = mock.Mock()
        protocol_helper.update_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        mock_share_exists = self.mock_object(self.library, '_share_exists')

        self.library.update_access(self.context,
                                   fake.SHARE,
                                   [fake.SHARE_ACCESS],
                                   [],
                                   [],
                                   share_server=fake.SHARE_SERVER)

        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)
        self.assertFalse(mock_share_exists.called)
        self.assertFalse(protocol_helper.set_client.called)
        self.assertFalse(protocol_helper.update_access.called)

    def test_update_access_share_not_found(self):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        protocol_helper = mock.Mock()
        protocol_helper.update_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=False))

        self.assertRaises(exception.ShareResourceNotFound,
                          self.library.update_access,
                          self.context,
                          fake.SHARE,
                          [fake.SHARE_ACCESS],
                          [],
                          [],
                          share_server=fake.SHARE_SERVER)

        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)
        share_name = self.library._get_backend_share_name(fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        self.assertFalse(protocol_helper.set_client.called)
        self.assertFalse(protocol_helper.update_access.called)

    def test_update_access_to_active_replica(self):
        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['replica_state'] = constants.REPLICA_STATE_ACTIVE
        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        protocol_helper = mock.Mock()
        protocol_helper.update_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=True))

        self.library.update_access(self.context,
                                   fake_share,
                                   [fake.SHARE_ACCESS],
                                   [],
                                   [],
                                   share_server=fake.SHARE_SERVER)

        mock_get_vserver.assert_called_once_with(
            share_server=fake.SHARE_SERVER)
        share_name = self.library._get_backend_share_name(fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        protocol_helper.set_client.assert_called_once_with(vserver_client)
        protocol_helper.update_access.assert_called_once_with(
            fake.SHARE, fake.SHARE_NAME, [fake.SHARE_ACCESS])

    def test_update_access_to_in_sync_replica(self):
        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['replica_state'] = constants.REPLICA_STATE_IN_SYNC
        self.library.update_access(self.context,
                                   fake_share,
                                   [fake.SHARE_ACCESS],
                                   [],
                                   [],
                                   share_server=fake.SHARE_SERVER)

    def test_setup_server(self):
        self.assertRaises(NotImplementedError,
                          self.library.setup_server,
                          fake.NETWORK_INFO)

    def test_teardown_server(self):
        self.assertRaises(NotImplementedError,
                          self.library.teardown_server,
                          fake.SHARE_SERVER['backend_details'])

    def test_get_network_allocations_number(self):
        self.assertRaises(NotImplementedError,
                          self.library.get_network_allocations_number)

    def test_update_ssc_info(self):

        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        mock_update_ssc_aggr_info = self.mock_object(self.library,
                                                     '_update_ssc_aggr_info')

        self.library._update_ssc_info()

        expected = {
            fake.AGGREGATES[0]: {
                'netapp_aggregate': fake.AGGREGATES[0],
            },
            fake.AGGREGATES[1]: {
                'netapp_aggregate': fake.AGGREGATES[1],
            }
        }

        self.assertDictEqual(expected, self.library._ssc_stats)
        self.assertTrue(mock_update_ssc_aggr_info.called)

    def test_update_ssc_info_no_aggregates(self):

        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=[]))
        mock_update_ssc_aggr_info = self.mock_object(self.library,
                                                     '_update_ssc_aggr_info')

        self.library._update_ssc_info()

        self.assertDictEqual({}, self.library._ssc_stats)
        self.assertFalse(mock_update_ssc_aggr_info.called)

    def test_update_ssc_aggr_info(self):

        self.library._have_cluster_creds = True
        mock_get_aggregate = self.mock_object(
            self.client, 'get_aggregate',
            mock.Mock(side_effect=fake.SSC_AGGREGATES))
        mock_get_aggregate_disk_types = self.mock_object(
            self.client, 'get_aggregate_disk_types',
            mock.Mock(side_effect=fake.SSC_DISK_TYPES))
        ssc_stats = {
            fake.AGGREGATES[0]: {
                'netapp_aggregate': fake.AGGREGATES[0],
            },
            fake.AGGREGATES[1]: {
                'netapp_aggregate': fake.AGGREGATES[1],
            },
        }

        self.library._update_ssc_aggr_info(fake.AGGREGATES, ssc_stats)

        self.assertDictEqual(fake.SSC_INFO, ssc_stats)
        mock_get_aggregate.assert_has_calls([
            mock.call(fake.AGGREGATES[0]),
            mock.call(fake.AGGREGATES[1]),
        ])
        mock_get_aggregate_disk_types.assert_has_calls([
            mock.call(fake.AGGREGATES[0]),
            mock.call(fake.AGGREGATES[1]),
        ])

    def test_update_ssc_aggr_info_not_found(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.client,
                         'get_aggregate',
                         mock.Mock(return_value={}))
        self.mock_object(self.client,
                         'get_aggregate_disk_types',
                         mock.Mock(return_value=None))
        ssc_stats = {
            fake.AGGREGATES[0]: {},
            fake.AGGREGATES[1]: {},
        }

        self.library._update_ssc_aggr_info(fake.AGGREGATES, ssc_stats)

        expected = {
            fake.AGGREGATES[0]: {
                'netapp_raid_type': None,
                'netapp_disk_type': None,
                'netapp_hybrid_aggregate': None,
            },
            fake.AGGREGATES[1]: {
                'netapp_raid_type': None,
                'netapp_disk_type': None,
                'netapp_hybrid_aggregate': None,
            }
        }
        self.assertDictEqual(expected, ssc_stats)

    def test_update_ssc_aggr_info_no_cluster_creds(self):

        self.library._have_cluster_creds = False
        ssc_stats = {}

        self.library._update_ssc_aggr_info(fake.AGGREGATES, ssc_stats)

        self.assertDictEqual({}, ssc_stats)
        self.assertFalse(self.library._client.get_aggregate_raid_types.called)

    def test_create_replica(self):
        self.mock_object(self.library,
                         '_allocate_container')
        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(data_motion, 'get_client_for_backend')
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))
        expected_model_update = {
            'export_locations': [],
            'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC,
            'access_rules_status': constants.STATUS_ACTIVE,
        }

        model_update = self.library.create_replica(
            None, [fake.SHARE], fake.SHARE, [], [],
            share_server=None)

        self.assertDictMatch(expected_model_update, model_update)
        mock_dm_session.create_snapmirror.assert_called_once_with(fake.SHARE,
                                                                  fake.SHARE)
        data_motion.get_client_for_backend.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1)

    def test_create_replica_with_share_server(self):
        self.mock_object(self.library,
                         '_allocate_container',
                         mock.Mock())
        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(data_motion, 'get_client_for_backend')
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))

        expected_model_update = {
            'export_locations': [],
            'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC,
            'access_rules_status': constants.STATUS_ACTIVE,
        }

        model_update = self.library.create_replica(
            None, [fake.SHARE], fake.SHARE, [], [],
            share_server=fake.SHARE_SERVER)

        self.assertDictMatch(expected_model_update, model_update)
        mock_dm_session.create_snapmirror.assert_called_once_with(fake.SHARE,
                                                                  fake.SHARE)
        data_motion.get_client_for_backend.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1)

    def test_delete_replica(self):

        active_replica = fake_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE)
        replica_1 = fake_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC,
            host=fake.MANILA_HOST_NAME)
        replica_2 = fake_replica(
            replica_state=constants.REPLICA_STATE_OUT_OF_SYNC)
        replica_list = [active_replica, replica_1, replica_2]

        self.mock_object(self.library,
                         '_deallocate_container',
                         mock.Mock())
        self.mock_object(self.library,
                         '_share_exists',
                         mock.Mock(return_value=False))
        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(data_motion, 'get_client_for_backend')
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))

        result = self.library.delete_replica(None,
                                             replica_list,
                                             replica_1,
                                             [],
                                             share_server=None)
        self.assertIsNone(result)
        mock_dm_session.delete_snapmirror.assert_has_calls([
            mock.call(active_replica, replica_1),
            mock.call(replica_2, replica_1),
            mock.call(replica_1, replica_2),
            mock.call(replica_1, active_replica)],
            any_order=True)
        self.assertEqual(4, mock_dm_session.delete_snapmirror.call_count)
        data_motion.get_client_for_backend.assert_called_with(
            fake.BACKEND_NAME, vserver_name=mock.ANY)
        self.assertEqual(1, data_motion.get_client_for_backend.call_count)

    def test_delete_replica_with_share_server(self):

        active_replica = fake_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE)
        replica = fake_replica(replica_state=constants.REPLICA_STATE_IN_SYNC,
                               host=fake.MANILA_HOST_NAME)
        replica_list = [active_replica, replica]

        self.mock_object(self.library,
                         '_deallocate_container',
                         mock.Mock())
        self.mock_object(self.library,
                         '_share_exists',
                         mock.Mock(return_value=False))
        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(data_motion, 'get_client_for_backend')
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))

        result = self.library.delete_replica(None,
                                             replica_list,
                                             replica,
                                             [],
                                             share_server=fake.SHARE_SERVER)
        self.assertIsNone(result)
        mock_dm_session.delete_snapmirror.assert_has_calls([
            mock.call(active_replica, replica),
            mock.call(replica, active_replica)],
            any_order=True)
        data_motion.get_client_for_backend.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1)

    def test_delete_replica_share_absent_on_backend(self):
        active_replica = fake_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE)
        replica = fake_replica(replica_state=constants.REPLICA_STATE_IN_SYNC,
                               host=fake.MANILA_HOST_NAME)
        replica_list = [active_replica, replica]

        self.mock_object(self.library,
                         '_deallocate_container',
                         mock.Mock())
        self.mock_object(self.library,
                         '_share_exists',
                         mock.Mock(return_value=False))
        mock_dm_session = mock.Mock()
        self.mock_object(data_motion,
                         "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(data_motion, 'get_client_for_backend')
        self.mock_object(mock_dm_session,
                         'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))

        result = self.library.delete_replica(None,
                                             replica_list,
                                             replica,
                                             [],
                                             share_server=None)

        self.assertIsNone(result)
        self.assertFalse(self.library._deallocate_container.called)
        mock_dm_session.delete_snapmirror.assert_has_calls([
            mock.call(active_replica, replica),
            mock.call(replica, active_replica)],
            any_order=True)
        data_motion.get_client_for_backend.assert_called_with(
            fake.BACKEND_NAME, vserver_name=mock.ANY)
        self.assertEqual(1, data_motion.get_client_for_backend.call_count)

    def test_update_replica_state_no_snapmirror_share_creating(self):
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(return_value=[])

        replica = copy.deepcopy(fake.SHARE)
        replica['status'] = constants.STATUS_CREATING

        result = self.library.update_replica_state(
            None, [replica], replica, None, [], share_server=None)

        self.assertFalse(self.mock_dm_session.create_snapmirror.called)
        self.assertEqual(constants.STATUS_OUT_OF_SYNC, result)

    def test_update_replica_state_share_reverting_to_snapshot(self):
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(return_value=[])

        replica = copy.deepcopy(fake.SHARE)
        replica['status'] = constants.STATUS_REVERTING

        result = self.library.update_replica_state(
            None, [replica], replica, None, [], share_server=None)

        self.assertFalse(self.mock_dm_session.get_snapmirrors.called)
        self.assertFalse(self.mock_dm_session.create_snapmirror.called)
        self.assertIsNone(result)

    def test_update_replica_state_no_snapmirror_create_failed(self):
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(return_value=[])
        self.mock_dm_session.create_snapmirror.side_effect = (
            netapp_api.NaApiError(code=0))

        replica = copy.deepcopy(fake.SHARE)
        replica['status'] = constants.REPLICA_STATE_OUT_OF_SYNC

        result = self.library.update_replica_state(
            None, [replica], replica, None, [], share_server=None)

        self.assertTrue(self.mock_dm_session.create_snapmirror.called)
        self.assertEqual(constants.STATUS_ERROR, result)

    @ddt.data(constants.STATUS_ERROR, constants.STATUS_AVAILABLE)
    def test_update_replica_state_no_snapmirror(self, status):
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(return_value=[])

        replica = copy.deepcopy(fake.SHARE)
        replica['status'] = status

        result = self.library.update_replica_state(
            None, [replica], replica, None, [], share_server=None)

        self.assertEqual(1, self.mock_dm_session.create_snapmirror.call_count)
        self.assertEqual(constants.STATUS_OUT_OF_SYNC, result)

    def test_update_replica_state_broken_snapmirror(self):
        fake_snapmirror = {
            'mirror-state': 'broken-off',
            'relationship-status': 'idle',
            'source-vserver': fake.VSERVER2,
            'source-volume': 'fake_volume',
            'last-transfer-end-timestamp': '%s' % float(time.time() - 10000)
        }
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(
            return_value=[fake_snapmirror])

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)

        vserver_client.resync_snapmirror.assert_called_once_with(
            fake.VSERVER2, 'fake_volume', fake.VSERVER1, fake.SHARE['name']
        )

        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC, result)

    def test_update_replica_state_snapmirror_still_initializing(self):
        fake_snapmirror = {
            'mirror-state': 'uninitialized',
            'relationship-status': 'transferring',
            'source-vserver': fake.VSERVER2,
            'source-volume': 'fake_volume',
            'last-transfer-end-timestamp': '%s' % float(time.time() - 10000)
        }
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(
            return_value=[fake_snapmirror])

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)

        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC, result)

    def test_update_replica_state_fail_to_get_snapmirrors(self):
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors.side_effect = (
            netapp_api.NaApiError(code=0))

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)
        self.assertTrue(self.mock_dm_session.get_snapmirrors.called)
        self.assertEqual(constants.STATUS_ERROR, result)

    def test_update_replica_state_broken_snapmirror_resync_error(self):
        fake_snapmirror = {
            'mirror-state': 'broken-off',
            'relationship-status': 'idle',
            'source-vserver': fake.VSERVER2,
            'source-volume': 'fake_volume',
            'last-transfer-end-timestamp': '%s' % float(time.time() - 10000)
        }
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(
            return_value=[fake_snapmirror])
        vserver_client.resync_snapmirror.side_effect = netapp_api.NaApiError

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)

        vserver_client.resync_snapmirror.assert_called_once_with(
            fake.VSERVER2, 'fake_volume', fake.VSERVER1, fake.SHARE['name']
        )

        self.assertEqual(constants.STATUS_ERROR, result)

    def test_update_replica_state_stale_snapmirror(self):
        fake_snapmirror = {
            'mirror-state': 'snapmirrored',
            'last-transfer-end-timestamp': '%s' % float(
                timeutils.utcnow_ts() - 10000)
        }
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(
            return_value=[fake_snapmirror])

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)

        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC, result)

    def test_update_replica_state_in_sync(self):
        fake_snapmirror = {
            'mirror-state': 'snapmirrored',
            'relationship-status': 'idle',
            'last-transfer-end-timestamp': '%s' % float(time.time())
        }
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(
            return_value=[fake_snapmirror])

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)

        self.assertEqual(constants.REPLICA_STATE_IN_SYNC, result)

    def test_update_replica_state_backend_volume_absent(self):
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.assertRaises(exception.ShareResourceNotFound,
                          self.library.update_replica_state,
                          None, [fake.SHARE], fake.SHARE, None, [],
                          share_server=None)

    def test_update_replica_state_in_sync_with_snapshots(self):
        fake_snapmirror = {
            'mirror-state': 'snapmirrored',
            'relationship-status': 'idle',
            'last-transfer-end-timestamp': '%s' % float(time.time())
        }
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = fake.SHARE['id']
        snapshots = [{'share_replica_snapshot': fake_snapshot}]
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'snapshot_exists', mock.Mock(
            return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(
            return_value=[fake_snapmirror])

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, snapshots,
                                                   share_server=None)

        self.assertEqual(constants.REPLICA_STATE_IN_SYNC, result)

    def test_update_replica_state_missing_snapshot(self):
        fake_snapmirror = {
            'mirror-state': 'snapmirrored',
            'relationship-status': 'idle',
            'last-transfer-end-timestamp': '%s' % float(time.time())
        }
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = fake.SHARE['id']
        snapshots = [{'share_replica_snapshot': fake_snapshot}]
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'snapshot_exists', mock.Mock(
            return_value=False))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(
            return_value=[fake_snapmirror])

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, snapshots,
                                                   share_server=None)

        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC, result)

    def test_promote_replica(self):
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock.Mock()))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))
        self.mock_object(self.library, '_handle_qos_on_replication_change')

        replicas = self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2],
            self.fake_replica_2, [], share_server=None)

        self.mock_dm_session.change_snapmirror_source.assert_called_once_with(
            self.fake_replica, self.fake_replica, self.fake_replica_2,
            mock.ANY
        )
        self.assertEqual(2, len(replicas))
        actual_replica_1 = list(filter(
            lambda x: x['id'] == self.fake_replica['id'], replicas))[0]
        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC,
                         actual_replica_1['replica_state'])
        actual_replica_2 = list(filter(
            lambda x: x['id'] == self.fake_replica_2['id'], replicas))[0]
        self.assertEqual(constants.REPLICA_STATE_ACTIVE,
                         actual_replica_2['replica_state'])
        self.assertEqual('fake_export_location',
                         actual_replica_2['export_locations'])
        self.assertEqual(constants.STATUS_ACTIVE,
                         actual_replica_2['access_rules_status'])
        self.library._handle_qos_on_replication_change.assert_called_once()

    def test_promote_replica_destination_unreachable(self):
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock.Mock()))
        self.mock_object(self.library, '_handle_qos_on_replication_change')

        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))
        self.mock_object(
            self.library, '_convert_destination_replica_to_independent',
            mock.Mock(side_effect=exception.StorageCommunicationException))

        replicas = self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2],
            self.fake_replica_2, [], share_server=None)

        self.assertEqual(1, len(replicas))
        actual_replica = replicas[0]
        self.assertEqual(constants.STATUS_ERROR,
                         actual_replica['replica_state'])
        self.assertEqual(constants.STATUS_ERROR,
                         actual_replica['status'])
        self.assertFalse(
            self.library._handle_qos_on_replication_change.called)

    def test_promote_replica_more_than_two_replicas(self):
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        fake_replica_3['replica_state'] = constants.REPLICA_STATE_OUT_OF_SYNC
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library, '_handle_qos_on_replication_change')
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock.Mock()))

        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))

        replicas = self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2, fake_replica_3],
            self.fake_replica_2, [], share_server=None)

        self.mock_dm_session.change_snapmirror_source.assert_has_calls([
            mock.call(fake_replica_3, self.fake_replica, self.fake_replica_2,
                      mock.ANY),
            mock.call(self.fake_replica, self.fake_replica,
                      self.fake_replica_2, mock.ANY)
        ], any_order=True)

        self.assertEqual(3, len(replicas))
        actual_replica_1 = list(filter(
            lambda x: x['id'] == self.fake_replica['id'], replicas))[0]
        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC,
                         actual_replica_1['replica_state'])
        actual_replica_2 = list(filter(
            lambda x: x['id'] == self.fake_replica_2['id'], replicas))[0]
        self.assertEqual(constants.REPLICA_STATE_ACTIVE,
                         actual_replica_2['replica_state'])
        self.assertEqual('fake_export_location',
                         actual_replica_2['export_locations'])
        actual_replica_3 = list(filter(
            lambda x: x['id'] == fake_replica_3['id'], replicas))[0]
        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC,
                         actual_replica_3['replica_state'])
        self.library._handle_qos_on_replication_change.assert_called_once()

    def test_promote_replica_with_access_rules(self):
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library, '_handle_qos_on_replication_change')
        mock_helper = mock.Mock()
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock_helper))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))

        replicas = self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2],
            self.fake_replica_2, [fake.SHARE_ACCESS], share_server=None)

        self.mock_dm_session.change_snapmirror_source.assert_has_calls([
            mock.call(self.fake_replica, self.fake_replica,
                      self.fake_replica_2, mock.ANY)
        ], any_order=True)
        self.assertEqual(2, len(replicas))
        share_name = self.library._get_backend_share_name(
            self.fake_replica_2['id'])
        mock_helper.update_access.assert_called_once_with(self.fake_replica_2,
                                                          share_name,
                                                          [fake.SHARE_ACCESS])
        self.library._handle_qos_on_replication_change.assert_called_once()

    @ddt.data({'extra_specs': {'netapp:snapshot_policy': 'none'},
               'have_cluster_creds': True},
              # Test Case 2 isn't possible input
              {'extra_specs': {'qos': True, 'netapp:maxiops': '3000'},
               'have_cluster_creds': False})
    @ddt.unpack
    def test_handle_qos_on_replication_change_nothing_to_handle(
            self, extra_specs, have_cluster_creds):

        self.library._have_cluster_creds = have_cluster_creds
        self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(lib_base.LOG, 'info')
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=extra_specs))

        retval = self.library._handle_qos_on_replication_change(
            self.mock_dm_session, self.fake_replica_2, self.fake_replica,
            share_server=fake.SHARE_SERVER)

        self.assertIsNone(retval)
        lib_base.LOG.exception.assert_not_called()
        lib_base.LOG.info.assert_not_called()

    def test_handle_qos_on_replication_change_exception(self):
        self.library._have_cluster_creds = True
        extra_specs = {'qos': True, fake.QOS_EXTRA_SPEC: '3000'}
        vserver_client = mock.Mock()
        self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(lib_base.LOG, 'info')
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=extra_specs))
        self.mock_object(self.library, '_get_vserver', mock.Mock(
            return_value=(fake.VSERVER1, vserver_client)))
        self.mock_object(self.library._client, 'qos_policy_group_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library._client, 'qos_policy_group_modify',
                         mock.Mock(side_effect=netapp_api.NaApiError))

        retval = self.library._handle_qos_on_replication_change(
            self.mock_dm_session, self.fake_replica_2, self.fake_replica,
            share_server=fake.SHARE_SERVER)

        self.assertIsNone(retval)
        (self.mock_dm_session.remove_qos_on_old_active_replica
         .assert_called_once_with(self.fake_replica))
        lib_base.LOG.exception.assert_called_once()
        lib_base.LOG.info.assert_not_called()
        vserver_client.set_qos_policy_group_for_volume.assert_not_called()

    def test_handle_qos_on_replication_change_modify_existing_policy(self):
        self.library._have_cluster_creds = True
        extra_specs = {'qos': True, fake.QOS_EXTRA_SPEC: '3000'}
        vserver_client = mock.Mock()
        volume_name_on_backend = self.library._get_backend_share_name(
            self.fake_replica_2['id'])
        self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(lib_base.LOG, 'info')
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=extra_specs))
        self.mock_object(self.library, '_get_vserver', mock.Mock(
            return_value=(fake.VSERVER1, vserver_client)))
        self.mock_object(self.library._client, 'qos_policy_group_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library._client, 'qos_policy_group_modify')
        self.mock_object(self.library, '_create_qos_policy_group')

        retval = self.library._handle_qos_on_replication_change(
            self.mock_dm_session, self.fake_replica_2, self.fake_replica,
            share_server=fake.SHARE_SERVER)

        self.assertIsNone(retval)
        self.library._client.qos_policy_group_modify.assert_called_once_with(
            'qos_' + volume_name_on_backend, '3000iops')
        vserver_client.set_qos_policy_group_for_volume.assert_called_once_with(
            volume_name_on_backend, 'qos_' + volume_name_on_backend)
        self.library._create_qos_policy_group.assert_not_called()
        lib_base.LOG.exception.assert_not_called()
        lib_base.LOG.info.assert_called_once()

    def test_handle_qos_on_replication_change_create_new_policy(self):
        self.library._have_cluster_creds = True
        extra_specs = {'qos': True, fake.QOS_EXTRA_SPEC: '3000'}
        vserver_client = mock.Mock()
        self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(lib_base.LOG, 'info')
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=extra_specs))
        self.mock_object(self.library, '_get_vserver', mock.Mock(
            return_value=(fake.VSERVER1, vserver_client)))
        self.mock_object(self.library._client, 'qos_policy_group_exists',
                         mock.Mock(return_value=False))
        self.mock_object(self.library._client, 'qos_policy_group_modify')
        self.mock_object(self.library, '_create_qos_policy_group')

        retval = self.library._handle_qos_on_replication_change(
            self.mock_dm_session, self.fake_replica_2, self.fake_replica,
            share_server=fake.SHARE_SERVER)

        self.assertIsNone(retval)
        self.library._create_qos_policy_group.assert_called_once_with(
            self.fake_replica_2, fake.VSERVER1, {'maxiops': '3000'})
        self.library._client.qos_policy_group_modify.assert_not_called()
        lib_base.LOG.exception.assert_not_called()
        lib_base.LOG.info.assert_called_once()

    def test_convert_destination_replica_to_independent(self):
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock.Mock()))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))

        replica = self.library._convert_destination_replica_to_independent(
            None, self.mock_dm_session, self.fake_replica,
            self.fake_replica_2, [], share_server=None)

        self.mock_dm_session.update_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2)
        self.mock_dm_session.break_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2)

        self.assertEqual('fake_export_location',
                         replica['export_locations'])
        self.assertEqual(constants.REPLICA_STATE_ACTIVE,
                         replica['replica_state'])

    def test_convert_destination_replica_to_independent_update_failed(self):
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock.Mock()))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))
        self.mock_object(
            self.mock_dm_session, 'update_snapmirror',
            mock.Mock(side_effect=exception.StorageCommunicationException))

        replica = self.library._convert_destination_replica_to_independent(
            None, self.mock_dm_session, self.fake_replica,
            self.fake_replica_2, [], share_server=None)

        self.mock_dm_session.update_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2)
        self.mock_dm_session.break_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2)

        self.assertEqual('fake_export_location',
                         replica['export_locations'])
        self.assertEqual(constants.REPLICA_STATE_ACTIVE,
                         replica['replica_state'])

    def test_promote_replica_fail_to_set_access_rules(self):
        fake_helper = mock.Mock()
        fake_helper.update_access.side_effect = Exception
        fake_access_rules = [
            {'access_to': "0.0.0.0",
             'access_level': constants.ACCESS_LEVEL_RO},
            {'access_to': "10.10.10.10",
             'access_level': constants.ACCESS_LEVEL_RW},
        ]
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library, '_handle_qos_on_replication_change')
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=fake_helper))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))

        replicas = self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2],
            self.fake_replica_2, fake_access_rules, share_server=None)

        self.mock_dm_session.change_snapmirror_source.assert_called_once_with(
            self.fake_replica, self.fake_replica, self.fake_replica_2,
            mock.ANY
        )

        self.assertEqual(2, len(replicas))
        actual_replica_1 = list(filter(
            lambda x: x['id'] == self.fake_replica['id'], replicas))[0]
        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC,
                         actual_replica_1['replica_state'])
        actual_replica_2 = list(filter(
            lambda x: x['id'] == self.fake_replica_2['id'], replicas))[0]
        self.assertEqual(constants.REPLICA_STATE_ACTIVE,
                         actual_replica_2['replica_state'])
        self.assertEqual('fake_export_location',
                         actual_replica_2['export_locations'])
        self.assertEqual(constants.SHARE_INSTANCE_RULES_SYNCING,
                         actual_replica_2['access_rules_status'])
        self.library._handle_qos_on_replication_change.assert_called_once()

    def test_convert_destination_replica_to_independent_with_access_rules(
            self):
        fake_helper = mock.Mock()
        fake_helper.update_access.side_effect = Exception
        fake_access_rules = [
            {'access_to': "0.0.0.0",
             'access_level': constants.ACCESS_LEVEL_RO},
            {'access_to': "10.10.10.10",
             'access_level': constants.ACCESS_LEVEL_RW},
        ]
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=fake_helper))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))

        replica = self.library._convert_destination_replica_to_independent(
            None, self.mock_dm_session, self.fake_replica,
            self.fake_replica_2, fake_access_rules, share_server=None)

        self.mock_dm_session.update_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2)
        self.mock_dm_session.break_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2)

        self.assertEqual('fake_export_location',
                         replica['export_locations'])
        self.assertEqual(constants.REPLICA_STATE_ACTIVE,
                         replica['replica_state'])
        self.assertEqual(constants.SHARE_INSTANCE_RULES_SYNCING,
                         replica['access_rules_status'])

    def test_convert_destination_replica_to_independent_failed_access_rules(
            self):
        fake_helper = mock.Mock()
        fake_access_rules = [
            {'access_to': "0.0.0.0",
             'access_level': constants.ACCESS_LEVEL_RO},
            {'access_to': "10.10.10.10",
             'access_level': constants.ACCESS_LEVEL_RW},
        ]
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=fake_helper))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))

        replica = self.library._convert_destination_replica_to_independent(
            None, self.mock_dm_session, self.fake_replica,
            self.fake_replica_2, fake_access_rules, share_server=None)

        self.mock_dm_session.update_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2)
        self.mock_dm_session.break_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2)

        fake_helper.assert_has_calls([
            mock.call.set_client(mock.ANY),
            mock.call.update_access(mock.ANY, mock.ANY, fake_access_rules),
        ])

        self.assertEqual('fake_export_location',
                         replica['export_locations'])
        self.assertEqual(constants.REPLICA_STATE_ACTIVE,
                         replica['replica_state'])
        self.assertEqual(constants.STATUS_ACTIVE,
                         replica['access_rules_status'])

    def test_safe_change_replica_source(self):
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        fake_replica_3['replica_state'] = constants.REPLICA_STATE_OUT_OF_SYNC
        replica = self.library._safe_change_replica_source(
            self.mock_dm_session, self.fake_replica, self.fake_replica_2,
            fake_replica_3, [self.fake_replica, self.fake_replica_2,
                             fake_replica_3]
        )
        self.assertEqual([], replica['export_locations'])
        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC,
                         replica['replica_state'])

    def test_safe_change_replica_source_destination_unreachable(self):
        self.mock_dm_session.change_snapmirror_source.side_effect = (
            exception.StorageCommunicationException
        )

        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        fake_replica_3['replica_state'] = constants.REPLICA_STATE_OUT_OF_SYNC
        replica = self.library._safe_change_replica_source(
            self.mock_dm_session, self.fake_replica, self.fake_replica_2,
            fake_replica_3, [self.fake_replica, self.fake_replica_2,
                             fake_replica_3]
        )
        self.assertEqual([], replica['export_locations'])
        self.assertEqual(constants.STATUS_ERROR,
                         replica['replica_state'])
        self.assertEqual(constants.STATUS_ERROR,
                         replica['status'])

    def test_safe_change_replica_source_error(self):
        self.mock_dm_session.change_snapmirror_source.side_effect = (
            netapp_api.NaApiError(code=0)
        )

        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        fake_replica_3['replica_state'] = constants.REPLICA_STATE_OUT_OF_SYNC
        replica = self.library._safe_change_replica_source(
            self.mock_dm_session, self.fake_replica, self.fake_replica_2,
            fake_replica_3, [self.fake_replica, self.fake_replica_2,
                             fake_replica_3]
        )
        self.assertEqual([], replica['export_locations'])
        self.assertEqual(constants.STATUS_ERROR,
                         replica['replica_state'])

    def test_create_replicated_snapshot(self):
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        replica_list = [self.fake_replica, self.fake_replica_2, fake_replica_3]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = self.fake_replica['id']
        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['id'] = uuidutils.generate_uuid()
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']
        fake_snapshot_3 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_3['id'] = uuidutils.generate_uuid()
        fake_snapshot_3['share_id'] = fake_replica_3['id']
        snapshot_list = [fake_snapshot, fake_snapshot_2, fake_snapshot_3]

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        model_list = self.library.create_replicated_snapshot(
            self.context, replica_list, snapshot_list,
            share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        vserver_client.create_snapshot.assert_called_once_with(share_name,
                                                               snapshot_name)
        self.assertEqual(3, len(model_list))
        for snapshot in model_list:
            self.assertEqual(snapshot['provider_location'], snapshot_name)
        actual_active_snapshot = list(filter(
            lambda x: x['id'] == fake_snapshot['id'], model_list))[0]
        self.assertEqual(constants.STATUS_AVAILABLE,
                         actual_active_snapshot['status'])
        actual_non_active_snapshot_list = list(filter(
            lambda x: x['id'] != fake_snapshot['id'], model_list))
        for snapshot in actual_non_active_snapshot_list:
            self.assertEqual(constants.STATUS_CREATING, snapshot['status'])
        self.mock_dm_session.update_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2),
             mock.call(self.fake_replica, fake_replica_3)],
            any_order=True
        )

    def test_create_replicated_snapshot_with_creating_replica(self):
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        fake_replica_3['host'] = None
        replica_list = [self.fake_replica, self.fake_replica_2, fake_replica_3]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = self.fake_replica['id']
        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['id'] = uuidutils.generate_uuid()
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']
        fake_snapshot_3 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_3['id'] = uuidutils.generate_uuid()
        fake_snapshot_3['share_id'] = fake_replica_3['id']
        snapshot_list = [fake_snapshot, fake_snapshot_2, fake_snapshot_3]

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        model_list = self.library.create_replicated_snapshot(
            self.context, replica_list, snapshot_list,
            share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        vserver_client.create_snapshot.assert_called_once_with(share_name,
                                                               snapshot_name)
        self.assertEqual(3, len(model_list))
        for snapshot in model_list:
            self.assertEqual(snapshot['provider_location'], snapshot_name)
        actual_active_snapshot = list(filter(
            lambda x: x['id'] == fake_snapshot['id'], model_list))[0]
        self.assertEqual(constants.STATUS_AVAILABLE,
                         actual_active_snapshot['status'])
        actual_non_active_snapshot_list = list(filter(
            lambda x: x['id'] != fake_snapshot['id'], model_list))
        for snapshot in actual_non_active_snapshot_list:
            self.assertEqual(constants.STATUS_CREATING, snapshot['status'])
        self.mock_dm_session.update_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2)],
            any_order=True
        )

    def test_create_replicated_snapshot_no_snapmirror(self):
        self.mock_dm_session.update_snapmirror.side_effect = [
            None,
            netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND)
        ]
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        replica_list = [self.fake_replica, self.fake_replica_2, fake_replica_3]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = self.fake_replica['id']
        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['id'] = uuidutils.generate_uuid()
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']
        fake_snapshot_3 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_3['id'] = uuidutils.generate_uuid()
        fake_snapshot_3['share_id'] = fake_replica_3['id']
        snapshot_list = [fake_snapshot, fake_snapshot_2, fake_snapshot_3]

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        model_list = self.library.create_replicated_snapshot(
            self.context, replica_list, snapshot_list,
            share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        vserver_client.create_snapshot.assert_called_once_with(share_name,
                                                               snapshot_name)
        self.assertEqual(3, len(model_list))
        for snapshot in model_list:
            self.assertEqual(snapshot['provider_location'], snapshot_name)
        actual_active_snapshot = list(filter(
            lambda x: x['id'] == fake_snapshot['id'], model_list))[0]
        self.assertEqual(constants.STATUS_AVAILABLE,
                         actual_active_snapshot['status'])
        actual_non_active_snapshot_list = list(filter(
            lambda x: x['id'] != fake_snapshot['id'], model_list))
        for snapshot in actual_non_active_snapshot_list:
            self.assertEqual(constants.STATUS_CREATING, snapshot['status'])
        self.mock_dm_session.update_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2),
             mock.call(self.fake_replica, fake_replica_3)],
            any_order=True
        )

    def test_create_replicated_snapshot_update_error(self):
        self.mock_dm_session.update_snapmirror.side_effect = [
            None,
            netapp_api.NaApiError()
        ]
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        replica_list = [self.fake_replica, self.fake_replica_2, fake_replica_3]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = self.fake_replica['id']
        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['id'] = uuidutils.generate_uuid()
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']
        fake_snapshot_3 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_3['id'] = uuidutils.generate_uuid()
        fake_snapshot_3['share_id'] = fake_replica_3['id']
        snapshot_list = [fake_snapshot, fake_snapshot_2, fake_snapshot_3]

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.assertRaises(netapp_api.NaApiError,
                          self.library.create_replicated_snapshot,
                          self.context, replica_list, snapshot_list,
                          share_server=fake.SHARE_SERVER)

    def test_delete_replicated_snapshot(self):
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        replica_list = [self.fake_replica, self.fake_replica_2, fake_replica_3]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = self.fake_replica['id']
        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name
        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['id'] = uuidutils.generate_uuid()
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']
        fake_snapshot_2['provider_location'] = snapshot_name
        fake_snapshot_3 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_3['id'] = uuidutils.generate_uuid()
        fake_snapshot_3['share_id'] = fake_replica_3['id']
        fake_snapshot_3['provider_location'] = snapshot_name

        snapshot_list = [fake_snapshot, fake_snapshot_2, fake_snapshot_3]

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.library.delete_replicated_snapshot(
            self.context, replica_list, snapshot_list,
            share_server=fake.SHARE_SERVER)

        vserver_client.delete_snapshot.assert_called_once_with(share_name,
                                                               snapshot_name)

        self.mock_dm_session.update_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2),
             mock.call(self.fake_replica, fake_replica_3)],
            any_order=True
        )

    def test_delete_replicated_snapshot_replica_still_creating(self):
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        fake_replica_3['host'] = None
        replica_list = [self.fake_replica, self.fake_replica_2, fake_replica_3]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = self.fake_replica['id']
        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name
        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['id'] = uuidutils.generate_uuid()
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']
        fake_snapshot_2['provider_location'] = snapshot_name
        fake_snapshot_3 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_3['id'] = uuidutils.generate_uuid()
        fake_snapshot_3['share_id'] = fake_replica_3['id']
        fake_snapshot_3['provider_location'] = snapshot_name

        snapshot_list = [fake_snapshot, fake_snapshot_2, fake_snapshot_3]

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.library.delete_replicated_snapshot(
            self.context, replica_list, snapshot_list,
            share_server=fake.SHARE_SERVER)

        vserver_client.delete_snapshot.assert_called_once_with(share_name,
                                                               snapshot_name)

        self.mock_dm_session.update_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2)],
            any_order=True
        )

    def test_delete_replicated_snapshot_missing_snapmirror(self):
        self.mock_dm_session.update_snapmirror.side_effect = [
            None,
            netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND)
        ]
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        replica_list = [self.fake_replica, self.fake_replica_2, fake_replica_3]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = self.fake_replica['id']
        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name
        fake_snapshot['busy'] = False

        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['id'] = uuidutils.generate_uuid()
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']
        fake_snapshot_2['provider_location'] = snapshot_name
        fake_snapshot_3 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_3['id'] = uuidutils.generate_uuid()
        fake_snapshot_3['share_id'] = fake_replica_3['id']
        fake_snapshot_3['provider_location'] = snapshot_name

        snapshot_list = [fake_snapshot, fake_snapshot_2, fake_snapshot_3]

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake_snapshot
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.library.delete_replicated_snapshot(
            self.context, replica_list, snapshot_list,
            share_server=fake.SHARE_SERVER)

        vserver_client.delete_snapshot.assert_called_once_with(share_name,
                                                               snapshot_name)

        self.mock_dm_session.update_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2),
             mock.call(self.fake_replica, fake_replica_3)],
            any_order=True
        )

    def test_delete_replicated_snapshot_update_error(self):
        self.mock_dm_session.update_snapmirror.side_effect = [
            None,
            netapp_api.NaApiError()
        ]
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        replica_list = [self.fake_replica, self.fake_replica_2, fake_replica_3]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = self.fake_replica['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name
        fake_snapshot['busy'] = False

        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['id'] = uuidutils.generate_uuid()
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']
        fake_snapshot_2['provider_location'] = snapshot_name
        fake_snapshot_3 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_3['id'] = uuidutils.generate_uuid()
        fake_snapshot_3['share_id'] = fake_replica_3['id']
        fake_snapshot_3['provider_location'] = snapshot_name

        snapshot_list = [fake_snapshot, fake_snapshot_2, fake_snapshot_3]

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake_snapshot
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.assertRaises(netapp_api.NaApiError,
                          self.library.delete_replicated_snapshot,
                          self.context, replica_list, snapshot_list,
                          share_server=fake.SHARE_SERVER)

    def test_update_replicated_snapshot_still_creating(self):
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = False
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        replica_list = [self.fake_replica, self.fake_replica_2]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['status'] = constants.STATUS_CREATING
        fake_snapshot['share_id'] = self.fake_replica_2['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name

        model_update = self.library.update_replicated_snapshot(
            replica_list, self.fake_replica_2, [fake_snapshot], fake_snapshot)

        self.assertIsNone(model_update)
        self.mock_dm_session.update_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2
        )

    def test_update_replicated_snapshot_still_creating_no_host(self):
        self.fake_replica_2['host'] = None
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = False
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        replica_list = [self.fake_replica, self.fake_replica_2]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['status'] = constants.STATUS_CREATING
        fake_snapshot['share_id'] = self.fake_replica_2['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name

        model_update = self.library.update_replicated_snapshot(
            replica_list, self.fake_replica_2, [fake_snapshot], fake_snapshot)

        self.assertIsNone(model_update)
        self.mock_dm_session.update_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2
        )

    def test_update_replicated_snapshot_no_snapmirror(self):
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = False
        self.mock_dm_session.update_snapmirror.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND)
        )
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        replica_list = [self.fake_replica, self.fake_replica_2]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['status'] = constants.STATUS_CREATING
        fake_snapshot['share_id'] = self.fake_replica_2['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name

        model_update = self.library.update_replicated_snapshot(
            replica_list, self.fake_replica_2, [fake_snapshot], fake_snapshot)

        self.assertIsNone(model_update)
        self.mock_dm_session.update_snapmirror.assert_called_once_with(
            self.fake_replica, self.fake_replica_2
        )

    def test_update_replicated_snapshot_update_error(self):
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = False
        self.mock_dm_session.update_snapmirror.side_effect = (
            netapp_api.NaApiError()
        )
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        replica_list = [self.fake_replica, self.fake_replica_2]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['status'] = constants.STATUS_CREATING
        fake_snapshot['share_id'] = self.fake_replica_2['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name

        self.assertRaises(netapp_api.NaApiError,
                          self.library.update_replicated_snapshot,
                          replica_list, self.fake_replica_2,
                          [fake_snapshot], fake_snapshot)

    def test_update_replicated_snapshot_still_deleting(self):
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = True
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        replica_list = [self.fake_replica]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['status'] = constants.STATUS_DELETING
        fake_snapshot['share_id'] = self.fake_replica['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name

        model_update = self.library.update_replicated_snapshot(
            replica_list, self.fake_replica, [fake_snapshot], fake_snapshot)

        self.assertIsNone(model_update)

    def test_update_replicated_snapshot_created(self):
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = True
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        replica_list = [self.fake_replica]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['status'] = constants.STATUS_CREATING
        fake_snapshot['share_id'] = self.fake_replica['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name

        model_update = self.library.update_replicated_snapshot(
            replica_list, self.fake_replica, [fake_snapshot], fake_snapshot)

        self.assertEqual(constants.STATUS_AVAILABLE, model_update['status'])
        self.assertEqual(snapshot_name, model_update['provider_location'])

    def test_update_replicated_snapshot_created_no_provider_location(self):
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = True
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        replica_list = [self.fake_replica, self.fake_replica_2]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['status'] = constants.STATUS_ACTIVE
        fake_snapshot['share_id'] = self.fake_replica['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name
        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['status'] = constants.STATUS_CREATING
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']

        model_update = self.library.update_replicated_snapshot(
            replica_list, self.fake_replica_2,
            [fake_snapshot, fake_snapshot_2], fake_snapshot_2)

        self.assertEqual(constants.STATUS_AVAILABLE, model_update['status'])
        self.assertEqual(snapshot_name, model_update['provider_location'])

    def test_update_replicated_snapshot_deleted(self):
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = False
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        replica_list = [self.fake_replica]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['status'] = constants.STATUS_DELETING
        fake_snapshot['share_id'] = self.fake_replica['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name

        self.assertRaises(exception.SnapshotResourceNotFound,
                          self.library.update_replicated_snapshot,
                          replica_list, self.fake_replica, [fake_snapshot],
                          fake_snapshot)

    def test_update_replicated_snapshot_no_provider_locations(self):
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = True
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        replica_list = [self.fake_replica]
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['status'] = constants.STATUS_CREATING
        fake_snapshot['share_id'] = self.fake_replica['id']
        fake_snapshot['provider_location'] = None

        model_update = self.library.update_replicated_snapshot(
            replica_list, self.fake_replica, [fake_snapshot], fake_snapshot)

        self.assertIsNone(model_update)

    def _get_fake_replicas_and_snapshots(self):

        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = self.fake_replica['id']
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])
        fake_snapshot['provider_location'] = snapshot_name
        fake_snapshot_2 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_2['id'] = uuidutils.generate_uuid()
        fake_snapshot_2['share_id'] = self.fake_replica_2['id']
        fake_snapshot_2['provider_location'] = snapshot_name
        fake_snapshot_3 = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot_3['id'] = uuidutils.generate_uuid()
        fake_snapshot_3['share_id'] = fake_replica_3['id']
        fake_snapshot_3['provider_location'] = snapshot_name
        replica_list = [self.fake_replica, self.fake_replica_2, fake_replica_3]
        snapshot_list = [fake_snapshot, fake_snapshot_2, fake_snapshot_3]
        return replica_list, snapshot_list

    @ddt.data(True, False)
    def test_revert_to_replicated_snapshot(self, use_snap_provider_location):

        replica_list, snapshot_list = self._get_fake_replicas_and_snapshots()
        fake_replica, fake_replica_2, fake_replica_3 = replica_list
        fake_snapshot, fake_snapshot_2, fake_snapshot_3 = snapshot_list

        if not use_snap_provider_location:
            del fake_snapshot['provider_location']
            del fake_snapshot_2['provider_location']
            del fake_snapshot_3['provider_location']

        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT
        vserver_client.list_snapmirror_snapshots.return_value = ['sm_snap']
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.library.revert_to_replicated_snapshot(
            self.context, self.fake_replica, replica_list, fake_snapshot,
            snapshot_list, share_server=fake.SHARE_SERVER)

        vserver_client.get_snapshot.assert_called_once_with(
            share_name, snapshot_name)
        vserver_client.list_snapmirror_snapshots.assert_called_once_with(
            share_name)
        vserver_client.delete_snapshot.assert_called_once_with(
            share_name, 'sm_snap', ignore_owners=True)
        vserver_client.restore_snapshot.assert_called_once_with(
            share_name, snapshot_name)

        self.mock_dm_session.break_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2, mount=False),
             mock.call(self.fake_replica, fake_replica_3, mount=False)],
            any_order=True)
        self.mock_dm_session.resync_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2),
             mock.call(self.fake_replica, fake_replica_3)],
            any_order=True)

    def test_revert_to_replicated_snapshot_not_found(self):

        replica_list, snapshot_list = self._get_fake_replicas_and_snapshots()
        fake_snapshot, fake_snapshot_2, fake_snapshot_3 = snapshot_list
        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.side_effect = netapp_api.NaApiError
        vserver_client.list_snapmirror_snapshots.return_value = ['sm_snap']
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        self.assertRaises(
            netapp_api.NaApiError, self.library.revert_to_replicated_snapshot,
            self.context, self.fake_replica, replica_list, fake_snapshot,
            snapshot_list, share_server=fake.SHARE_SERVER)

        vserver_client.get_snapshot.assert_called_once_with(
            share_name, snapshot_name)
        self.assertFalse(vserver_client.list_snapmirror_snapshots.called)
        self.assertFalse(vserver_client.delete_snapshot.called)
        self.assertFalse(vserver_client.restore_snapshot.called)
        self.assertFalse(self.mock_dm_session.break_snapmirror.called)
        self.assertFalse(self.mock_dm_session.resync_snapmirror.called)

    def test_revert_to_replicated_snapshot_snapmirror_break_error(self):

        replica_list, snapshot_list = self._get_fake_replicas_and_snapshots()
        fake_snapshot, fake_snapshot_2, fake_snapshot_3 = snapshot_list

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT
        vserver_client.list_snapmirror_snapshots.return_value = ['sm_snap']
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.break_snapmirror.side_effect = (
            netapp_api.NaApiError)

        self.assertRaises(
            netapp_api.NaApiError, self.library.revert_to_replicated_snapshot,
            self.context, self.fake_replica, replica_list, fake_snapshot,
            snapshot_list, share_server=fake.SHARE_SERVER)

    def test_revert_to_replicated_snapshot_snapmirror_break_not_found(self):

        replica_list, snapshot_list = self._get_fake_replicas_and_snapshots()
        fake_replica, fake_replica_2, fake_replica_3 = replica_list
        fake_snapshot, fake_snapshot_2, fake_snapshot_3 = snapshot_list
        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT
        vserver_client.list_snapmirror_snapshots.return_value = ['sm_snap']
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.break_snapmirror.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND))

        self.library.revert_to_replicated_snapshot(
            self.context, self.fake_replica, replica_list, fake_snapshot,
            snapshot_list, share_server=fake.SHARE_SERVER)

        vserver_client.get_snapshot.assert_called_once_with(
            share_name, snapshot_name)
        vserver_client.list_snapmirror_snapshots.assert_called_once_with(
            share_name)
        vserver_client.delete_snapshot.assert_called_once_with(
            share_name, 'sm_snap', ignore_owners=True)
        vserver_client.restore_snapshot.assert_called_once_with(
            share_name, snapshot_name)

        self.mock_dm_session.break_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2, mount=False),
             mock.call(self.fake_replica, fake_replica_3, mount=False)],
            any_order=True)
        self.mock_dm_session.resync_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2),
             mock.call(self.fake_replica, fake_replica_3)],
            any_order=True)

    def test_revert_to_replicated_snapshot_snapmirror_resync_error(self):

        replica_list, snapshot_list = self._get_fake_replicas_and_snapshots()
        fake_snapshot, fake_snapshot_2, fake_snapshot_3 = snapshot_list

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT
        vserver_client.list_snapmirror_snapshots.return_value = ['sm_snap']
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.resync_snapmirror.side_effect = (
            netapp_api.NaApiError)

        self.assertRaises(
            netapp_api.NaApiError, self.library.revert_to_replicated_snapshot,
            self.context, self.fake_replica, replica_list, fake_snapshot,
            snapshot_list, share_server=fake.SHARE_SERVER)

    def test_revert_to_replicated_snapshot_snapmirror_resync_not_found(self):

        replica_list, snapshot_list = self._get_fake_replicas_and_snapshots()
        fake_replica, fake_replica_2, fake_replica_3 = replica_list
        fake_snapshot, fake_snapshot_2, fake_snapshot_3 = snapshot_list
        share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id'])

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT
        vserver_client.list_snapmirror_snapshots.return_value = ['sm_snap']
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.resync_snapmirror.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND))

        self.library.revert_to_replicated_snapshot(
            self.context, self.fake_replica, replica_list, fake_snapshot,
            snapshot_list, share_server=fake.SHARE_SERVER)

        vserver_client.get_snapshot.assert_called_once_with(
            share_name, snapshot_name)
        vserver_client.list_snapmirror_snapshots.assert_called_once_with(
            share_name)
        vserver_client.delete_snapshot.assert_called_once_with(
            share_name, 'sm_snap', ignore_owners=True)
        vserver_client.restore_snapshot.assert_called_once_with(
            share_name, snapshot_name)

        self.mock_dm_session.break_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2, mount=False),
             mock.call(self.fake_replica, fake_replica_3, mount=False)],
            any_order=True)
        self.mock_dm_session.resync_snapmirror.assert_has_calls(
            [mock.call(self.fake_replica, self.fake_replica_2),
             mock.call(self.fake_replica, fake_replica_3)],
            any_order=True)

    def test_migration_check_compatibility_no_cluster_credentials(self):
        self.library._have_cluster_creds = False
        self.mock_object(data_motion, 'get_backend_configuration')
        mock_warning_log = self.mock_object(lib_base.LOG, 'warning')

        migration_compatibility = self.library.migration_check_compatibility(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), share_server=None,
            destination_share_server=fake.SHARE_SERVER)

        expected_compatibility = {
            'compatible': False,
            'writable': False,
            'nondisruptive': False,
            'preserve_metadata': False,
            'preserve_snapshots': False,
        }
        self.assertDictMatch(expected_compatibility, migration_compatibility)
        mock_warning_log.assert_called_once()
        self.assertFalse(data_motion.get_backend_configuration.called)

    @ddt.data((None, exception.NetAppException),
              (exception.Invalid, None))
    @ddt.unpack
    def test_migration_check_compatibility_extra_specs_invalid(
            self, side_effect_1, side_effect_2):
        self.library._have_cluster_creds = True
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity',
                         mock.Mock(side_effect=side_effect_1))
        self.mock_object(self.library,
                         '_check_aggregate_extra_specs_validity',
                         mock.Mock(side_effect=side_effect_2))
        self.mock_object(data_motion, 'get_backend_configuration')

        migration_compatibility = self.library.migration_check_compatibility(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), share_server=fake.SHARE_SERVER,
            destination_share_server=None)

        expected_compatibility = {
            'compatible': False,
            'writable': False,
            'nondisruptive': False,
            'preserve_metadata': False,
            'preserve_snapshots': False,
        }
        self.assertDictMatch(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        self.assertFalse(data_motion.get_backend_configuration.called)

    def test_migration_check_compatibility_destination_not_configured(self):
        self.library._have_cluster_creds = True
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(
            data_motion, 'get_backend_configuration',
            mock.Mock(side_effect=exception.BadConfigurationException))
        self.mock_object(self.library, '_get_vserver')
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value='destination_backend'))
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        mock_vserver_compatibility_check = self.mock_object(
            self.library, '_check_destination_vserver_for_vol_move')
        self.mock_object(self.library, '_get_dest_flexvol_encryption_value',
                         mock.Mock(return_value=False))

        migration_compatibility = self.library.migration_check_compatibility(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), share_server=fake.SHARE_SERVER,
            destination_share_server=None)

        expected_compatibility = {
            'compatible': False,
            'writable': False,
            'nondisruptive': False,
            'preserve_metadata': False,
            'preserve_snapshots': False,
        }
        self.assertDictMatch(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        self.assertFalse(mock_vserver_compatibility_check.called)
        self.assertFalse(self.library._get_vserver.called)

    @ddt.data(
        utils.annotated(
            'dest_share_server_not_expected',
            (('src_vserver', None), exception.InvalidParameterValue)),
        utils.annotated(
            'src_share_server_not_expected',
            (exception.InvalidParameterValue, ('dest_vserver', None))))
    def test_migration_check_compatibility_errors(self, side_effects):
        self.library._have_cluster_creds = True
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(data_motion, 'get_backend_configuration')
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=side_effects))
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value='destination_backend'))
        mock_compatibility_check = self.mock_object(
            self.client, 'check_volume_move')

        migration_compatibility = self.library.migration_check_compatibility(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), share_server=fake.SHARE_SERVER,
            destination_share_server=None)

        expected_compatibility = {
            'compatible': False,
            'writable': False,
            'nondisruptive': False,
            'preserve_metadata': False,
            'preserve_snapshots': False,
        }
        self.assertDictMatch(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        self.assertFalse(mock_compatibility_check.called)

    def test_migration_check_compatibility_incompatible_vservers(self):
        self.library._have_cluster_creds = True
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(data_motion, 'get_backend_configuration')
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        get_vserver_returns = [
            (fake.VSERVER1, mock.Mock()),
            (fake.VSERVER2, mock.Mock()),
        ]
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=get_vserver_returns))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=['destination_backend', 'destination_pool']))
        mock_move_check = self.mock_object(self.client, 'check_volume_move')

        migration_compatibility = self.library.migration_check_compatibility(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')

        expected_compatibility = {
            'compatible': False,
            'writable': False,
            'nondisruptive': False,
            'preserve_metadata': False,
            'preserve_snapshots': False,
        }
        self.assertDictMatch(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        self.assertFalse(mock_move_check.called)
        self.library._get_vserver.assert_has_calls(
            [mock.call(share_server=fake.SHARE_SERVER),
             mock.call(share_server='dst_srv')])

    def test_migration_check_compatibility_client_error(self):
        self.library._have_cluster_creds = True
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(data_motion, 'get_backend_configuration')
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=['destination_backend', 'destination_pool']))
        mock_move_check = self.mock_object(
            self.client, 'check_volume_move',
            mock.Mock(side_effect=netapp_api.NaApiError))
        self.mock_object(self.library, '_get_dest_flexvol_encryption_value',
                         mock.Mock(return_value=False))

        migration_compatibility = self.library.migration_check_compatibility(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')

        expected_compatibility = {
            'compatible': False,
            'writable': False,
            'nondisruptive': False,
            'preserve_metadata': False,
            'preserve_snapshots': False,
        }
        self.assertDictMatch(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        mock_move_check.assert_called_once_with(
            fake.SHARE_NAME, fake.VSERVER1, 'destination_pool',
            encrypt_destination=False)
        self.library._get_vserver.assert_has_calls(
            [mock.call(share_server=fake.SHARE_SERVER),
             mock.call(share_server='dst_srv')])

    def test_migration_check_compatibility(self):
        self.library._have_cluster_creds = True
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(data_motion, 'get_backend_configuration')
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=['destination_backend', 'destination_pool']))
        mock_move_check = self.mock_object(self.client, 'check_volume_move')
        self.mock_object(self.library, '_get_dest_flexvol_encryption_value',
                         mock.Mock(return_value=False))

        migration_compatibility = self.library.migration_check_compatibility(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')

        expected_compatibility = {
            'compatible': True,
            'writable': True,
            'nondisruptive': True,
            'preserve_metadata': True,
            'preserve_snapshots': True,
        }
        self.assertDictMatch(expected_compatibility, migration_compatibility)
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        mock_move_check.assert_called_once_with(
            fake.SHARE_NAME, fake.VSERVER1, 'destination_pool',
            encrypt_destination=False)
        self.library._get_vserver.assert_has_calls(
            [mock.call(share_server=fake.SHARE_SERVER),
             mock.call(share_server='dst_srv')])

    def test_migration_check_compatibility_destination_type_is_encrypted(self):
        self.library._have_cluster_creds = True
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(data_motion, 'get_backend_configuration')
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=['destination_backend', 'destination_pool']))
        mock_move_check = self.mock_object(self.client, 'check_volume_move')
        self.mock_object(self.library, '_get_dest_flexvol_encryption_value',
                         mock.Mock(return_value=True))
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={'spec1': 'spec-data'}))
        self.mock_object(self.library,
                         '_check_extra_specs_validity')
        self.mock_object(self.library,
                         '_check_aggregate_extra_specs_validity')

        migration_compatibility = self.library.migration_check_compatibility(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')

        expected_compatibility = {
            'compatible': True,
            'writable': True,
            'nondisruptive': True,
            'preserve_metadata': True,
            'preserve_snapshots': True,
        }
        self.assertDictMatch(expected_compatibility, migration_compatibility)
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')

        mock_move_check.assert_called_once_with(
            fake.SHARE_NAME, fake.VSERVER1, 'destination_pool',
            encrypt_destination=True)

        self.library._get_vserver.assert_has_calls(
            [mock.call(share_server=fake.SHARE_SERVER),
             mock.call(share_server='dst_srv')])

    def test_migration_start(self):
        mock_info_log = self.mock_object(lib_base.LOG, 'info')
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host',
                         mock.Mock(return_value='destination_pool'))
        mock_move = self.mock_object(self.client, 'start_volume_move')
        self.mock_object(self.library, '_get_dest_flexvol_encryption_value',
                         mock.Mock(return_value=False))

        retval = self.library.migration_start(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(),
            source_snapshots, snapshot_mappings,
            share_server=fake.SHARE_SERVER, destination_share_server='dst_srv')

        self.assertIsNone(retval)
        self.assertTrue(mock_info_log.called)
        mock_move.assert_called_once_with(
            fake.SHARE_NAME, fake.VSERVER1, 'destination_pool',
            encrypt_destination=False)

    def test_migration_start_encrypted_destination(self):
        mock_info_log = self.mock_object(lib_base.LOG, 'info')
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host',
                         mock.Mock(return_value='destination_pool'))
        mock_move = self.mock_object(self.client, 'start_volume_move')
        self.mock_object(self.library, '_get_dest_flexvol_encryption_value',
                         mock.Mock(return_value=True))

        retval = self.library.migration_start(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(),
            source_snapshots, snapshot_mappings,
            share_server=fake.SHARE_SERVER, destination_share_server='dst_srv')

        self.assertIsNone(retval)
        self.assertTrue(mock_info_log.called)
        mock_move.assert_called_once_with(
            fake.SHARE_NAME, fake.VSERVER1, 'destination_pool',
            encrypt_destination=True)

    def test_migration_continue_volume_move_failed(self):
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        mock_status_check = self.mock_object(
            self.client, 'get_volume_move_status',
            mock.Mock(return_value={'phase': 'failed', 'details': 'unknown'}))

        self.assertRaises(exception.NetAppException,
                          self.library.migration_continue,
                          self.context, fake_share.fake_share_instance(),
                          fake_share.fake_share_instance(),
                          source_snapshots, snapshot_mappings,
                          share_server=None, destination_share_server=None)

        mock_status_check.assert_called_once_with(
            fake.SHARE_NAME, fake.VSERVER1)
        mock_exception_log.assert_called_once()

    @ddt.data({'phase': 'Queued', 'completed': False},
              {'phase': 'Finishing', 'completed': False},
              {'phase': 'cutover_hard_deferred', 'completed': True},
              {'phase': 'cutover_soft_deferred', 'completed': True},
              {'phase': 'completed', 'completed': True})
    @ddt.unpack
    def test_migration_continue(self, phase, completed):
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(self.client, 'get_volume_move_status',
                         mock.Mock(return_value={'phase': phase}))

        migration_completed = self.library.migration_continue(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), source_snapshots,
            snapshot_mappings, share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')

        self.assertEqual(completed, migration_completed)

    @ddt.data('cutover_hard_deferred', 'cutover_soft_deferred',
              'Queued', 'Replicating')
    def test_migration_get_progress_at_phase(self, phase):
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        mock_info_log = self.mock_object(lib_base.LOG, 'info')
        status = {
            'state': 'healthy',
            'details': '%s:: Volume move job in progress' % phase,
            'phase': phase,
            'estimated-completion-time': '1481919246',
            'percent-complete': 80,
        }
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(self.client, 'get_volume_move_status',
                         mock.Mock(return_value=status))

        migration_progress = self.library.migration_get_progress(
            self.context, fake_share.fake_share_instance(),
            source_snapshots, snapshot_mappings,
            fake_share.fake_share_instance(), share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')

        expected_progress = {
            'total_progress': 100 if phase.startswith('cutover') else 80,
            'state': 'healthy',
            'estimated_completion_time': '1481919246',
            'details': '%s:: Volume move job in progress' % phase,
            'phase': phase,
        }
        self.assertDictMatch(expected_progress, migration_progress)
        mock_info_log.assert_called_once()

    @ddt.data(utils.annotated('already_canceled', (True, )),
              utils.annotated('not_canceled_yet', (False, )))
    def test_migration_cancel(self, already_canceled):
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        already_canceled = already_canceled[0]
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        mock_info_log = self.mock_object(lib_base.LOG, 'info')
        vol_move_side_effect = (exception.NetAppException
                                if already_canceled else None)
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(self.client, 'abort_volume_move')
        self.mock_object(self.client, 'get_volume_move_status',
                         mock.Mock(side_effect=vol_move_side_effect))

        retval = self.library.migration_cancel(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), source_snapshots,
            snapshot_mappings, share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')

        self.assertIsNone(retval)
        if already_canceled:
            mock_exception_log.assert_called_once()
        else:
            mock_info_log.assert_called_once()
        self.assertEqual(not already_canceled,
                         self.client.abort_volume_move.called)

    def test_migration_complete_invalid_phase(self):
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        status = {
            'state': 'healthy',
            'phase': 'Replicating',
            'details': 'Replicating:: Volume move operation is in progress.',
        }
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        vserver_client = mock.Mock()
        self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(side_effect=[fake.SHARE_NAME, 'new_share_name']))
        self.mock_object(self.library, '_get_volume_move_status',
                         mock.Mock(return_value=status))
        self.mock_object(self.library, '_create_export')

        self.assertRaises(
            exception.NetAppException, self.library.migration_complete,
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance, source_snapshots,
            snapshot_mappings, share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')
        self.assertFalse(vserver_client.set_volume_name.called)
        self.assertFalse(self.library._create_export.called)
        mock_exception_log.assert_called_once()

    def test_migration_complete_timeout(self):
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        self.library.configuration.netapp_volume_move_cutover_timeout = 15
        vol_move_side_effects = [
            {'phase': 'cutover_hard_deferred'},
            {'phase': 'Cutover'},
            {'phase': 'Finishing'},
            {'phase': 'Finishing'},
        ]
        self.mock_object(time, 'sleep')
        mock_warning_log = self.mock_object(lib_base.LOG, 'warning')
        vserver_client = mock.Mock()
        self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(side_effect=[fake.SHARE_NAME, 'new_share_name']))
        self.mock_object(self.library, '_get_volume_move_status', mock.Mock(
            side_effect=vol_move_side_effects))
        self.mock_object(self.library, '_create_export')
        src_share = fake_share.fake_share_instance(id='source-share-instance')
        dest_share = fake_share.fake_share_instance(id='dest-share-instance')

        self.assertRaises(
            exception.NetAppException, self.library.migration_complete,
            self.context, src_share, dest_share, source_snapshots,
            snapshot_mappings, share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')
        self.assertFalse(vserver_client.set_volume_name.called)
        self.assertFalse(self.library._create_export.called)
        self.assertEqual(3, mock_warning_log.call_count)

    @ddt.data('cutover_hard_deferred', 'cutover_soft_deferred', 'completed')
    def test_migration_complete(self, phase):
        snap = fake_share.fake_snapshot_instance(
            id='src-snapshot', provider_location='test-src-provider-location')
        dest_snap = fake_share.fake_snapshot_instance(id='dest-snapshot',
                                                      as_primitive=True)
        source_snapshots = [snap]
        snapshot_mappings = {snap['id']: dest_snap}
        self.library.configuration.netapp_volume_move_cutover_timeout = 15
        vol_move_side_effects = [
            {'phase': phase},
            {'phase': 'Cutover'},
            {'phase': 'Finishing'},
            {'phase': 'completed'},
        ]
        self.mock_object(time, 'sleep')
        mock_debug_log = self.mock_object(lib_base.LOG, 'debug')
        mock_info_log = self.mock_object(lib_base.LOG, 'info')
        mock_warning_log = self.mock_object(lib_base.LOG, 'warning')
        vserver_client = mock.Mock()
        self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(side_effect=[fake.SHARE_NAME, 'new_share_name']))
        self.mock_object(self.library, '_create_export', mock.Mock(
            return_value=fake.NFS_EXPORTS))
        mock_move_status_check = self.mock_object(
            self.library, '_get_volume_move_status',
            mock.Mock(side_effect=vol_move_side_effects))
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=fake.EXTRA_SPEC))
        self.mock_object(
            self.library, '_get_provisioning_options',
            mock.Mock(return_value=fake.PROVISIONING_OPTIONS_WITH_QOS))
        self.mock_object(
            self.library, '_modify_or_create_qos_for_existing_share',
            mock.Mock(return_value=fake.QOS_POLICY_GROUP_NAME))
        self.mock_object(vserver_client, 'modify_volume')

        src_share = fake_share.fake_share_instance(id='source-share-instance')
        dest_share = fake_share.fake_share_instance(id='dest-share-instance')
        dest_aggr = share_utils.extract_host(dest_share['host'], level='pool')

        data_updates = self.library.migration_complete(
            self.context, src_share, dest_share, source_snapshots,
            snapshot_mappings, share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')

        self.assertEqual(fake.NFS_EXPORTS, data_updates['export_locations'])
        expected_dest_snap_updates = {
            'provider_location': snap['provider_location'],
        }
        self.assertIn(dest_snap['id'], data_updates['snapshot_updates'])
        self.assertEqual(expected_dest_snap_updates,
                         data_updates['snapshot_updates'][dest_snap['id']])
        vserver_client.set_volume_name.assert_called_once_with(
            fake.SHARE_NAME, 'new_share_name')
        self.library._create_export.assert_called_once_with(
            dest_share, fake.SHARE_SERVER, fake.VSERVER1, vserver_client,
            clear_current_export_policy=False)
        vserver_client.modify_volume.assert_called_once_with(
            dest_aggr, 'new_share_name', **fake.PROVISIONING_OPTIONS_WITH_QOS)
        mock_info_log.assert_called_once()
        if phase != 'completed':
            self.assertEqual(2, mock_warning_log.call_count)
            self.assertFalse(mock_debug_log.called)
            self.assertEqual(4, mock_move_status_check.call_count)
        else:
            self.assertFalse(mock_warning_log.called)
            mock_debug_log.assert_called_once()
            mock_move_status_check.assert_called_once()

    def test_modify_or_create_qos_for_existing_share_no_qos_extra_specs(self):
        vserver_client = mock.Mock()
        self.mock_object(self.library, '_get_backend_qos_policy_group_name')
        self.mock_object(vserver_client, 'get_volume')
        self.mock_object(self.library, '_create_qos_policy_group')

        retval = self.library._modify_or_create_qos_for_existing_share(
            fake.SHARE, fake.EXTRA_SPEC, fake.VSERVER1, vserver_client)

        self.assertIsNone(retval)
        self.library._get_backend_qos_policy_group_name.assert_not_called()
        vserver_client.get_volume.assert_not_called()
        self.library._create_qos_policy_group.assert_not_called()

    def test_modify_or_create_qos_for_existing_share_no_existing_qos(self):
        vserver_client = mock.Mock()
        self.mock_object(self.library, '_get_backend_qos_policy_group_name')
        self.mock_object(vserver_client, 'get_volume',
                         mock.Mock(return_value=fake.FLEXVOL_WITHOUT_QOS))
        self.mock_object(self.library, '_create_qos_policy_group')
        self.mock_object(self.library._client, 'qos_policy_group_modify')
        qos_policy_name = self.library._get_backend_qos_policy_group_name(
            fake.SHARE['id'])

        retval = self.library._modify_or_create_qos_for_existing_share(
            fake.SHARE, fake.EXTRA_SPEC_WITH_QOS, fake.VSERVER1,
            vserver_client)

        share_obj = {
            'size': 2,
            'id': fake.SHARE['id'],
        }
        self.assertEqual(qos_policy_name, retval)
        self.library._client.qos_policy_group_modify.assert_not_called()
        self.library._create_qos_policy_group.assert_called_once_with(
            share_obj, fake.VSERVER1, {'maxiops': '3000'})

    @ddt.data(utils.annotated('volume_has_shared_qos_policy', (2, )),
              utils.annotated('volume_has_nonshared_qos_policy', (1, )))
    def test_modify_or_create_qos_for_existing_share(self, num_workloads):
        vserver_client = mock.Mock()
        num_workloads = num_workloads[0]
        qos_policy = copy.deepcopy(fake.QOS_POLICY_GROUP)
        qos_policy['num-workloads'] = num_workloads
        extra_specs = fake.EXTRA_SPEC_WITH_QOS
        self.mock_object(vserver_client, 'get_volume',
                         mock.Mock(return_value=fake.FLEXVOL_WITH_QOS))
        self.mock_object(self.library._client, 'qos_policy_group_get',
                         mock.Mock(return_value=qos_policy))
        mock_qos_policy_modify = self.mock_object(
            self.library._client, 'qos_policy_group_modify')
        mock_qos_policy_rename = self.mock_object(
            self.library._client, 'qos_policy_group_rename')
        mock_create_qos_policy = self.mock_object(
            self.library, '_create_qos_policy_group')
        new_qos_policy_name = self.library._get_backend_qos_policy_group_name(
            fake.SHARE['id'])

        retval = self.library._modify_or_create_qos_for_existing_share(
            fake.SHARE, extra_specs, fake.VSERVER1, vserver_client)

        self.assertEqual(new_qos_policy_name, retval)
        if num_workloads == 1:
            mock_create_qos_policy.assert_not_called()
            mock_qos_policy_modify.assert_called_once_with(
                fake.QOS_POLICY_GROUP_NAME, '3000iops')
            mock_qos_policy_rename.assert_called_once_with(
                fake.QOS_POLICY_GROUP_NAME, new_qos_policy_name)
        else:
            share_obj = {
                'size': 2,
                'id': fake.SHARE['id'],
            }
            mock_create_qos_policy.assert_called_once_with(
                share_obj, fake.VSERVER1, {'maxiops': '3000'})
            self.library._client.qos_policy_group_modify.assert_not_called()
            self.library._client.qos_policy_group_rename.assert_not_called()

    @ddt.data(('host', True), ('pool', False), (None, False), ('fake', False))
    @ddt.unpack
    def test__is_group_cg(self, css, is_cg):
        share_group = mock.Mock()
        share_group.consistent_snapshot_support = css
        self.assertEqual(is_cg,
                         self.library._is_group_cg(self.context, share_group))

    def test_create_group_snapshot_cg(self):
        share_group = mock.Mock()
        share_group.consistent_snapshot_support = 'host'
        snap_dict = {'share_group': share_group}
        fallback_create = mock.Mock()
        mock_create_cgsnapshot = self.mock_object(self.library,
                                                  'create_cgsnapshot')
        self.library.create_group_snapshot(self.context, snap_dict,
                                           fallback_create,
                                           share_server=fake.SHARE_SERVER)
        mock_create_cgsnapshot.assert_called_once_with(
            self.context, snap_dict, share_server=fake.SHARE_SERVER)
        fallback_create.assert_not_called()

    @ddt.data('pool', None, 'fake')
    def test_create_group_snapshot_fallback(self, css):
        share_group = mock.Mock()
        share_group.consistent_snapshot_support = css
        snap_dict = {'share_group': share_group}
        fallback_create = mock.Mock()
        mock_create_cgsnapshot = self.mock_object(self.library,
                                                  'create_cgsnapshot')
        self.library.create_group_snapshot(self.context, snap_dict,
                                           fallback_create,
                                           share_server=fake.SHARE_SERVER)
        mock_create_cgsnapshot.assert_not_called()
        fallback_create.assert_called_once_with(self.context,
                                                snap_dict,
                                                share_server=fake.SHARE_SERVER)

    def test_delete_group_snapshot_cg(self):
        share_group = mock.Mock()
        share_group.consistent_snapshot_support = 'host'
        snap_dict = {'share_group': share_group}
        fallback_delete = mock.Mock()
        mock_delete_cgsnapshot = self.mock_object(self.library,
                                                  'delete_cgsnapshot')
        self.library.delete_group_snapshot(self.context, snap_dict,
                                           fallback_delete,
                                           share_server=fake.SHARE_SERVER)
        mock_delete_cgsnapshot.assert_called_once_with(
            self.context, snap_dict, share_server=fake.SHARE_SERVER)
        fallback_delete.assert_not_called()

    @ddt.data('pool', None, 'fake')
    def test_delete_group_snapshot_fallback(self, css):
        share_group = mock.Mock()
        share_group.consistent_snapshot_support = css
        snap_dict = {'share_group': share_group}
        fallback_delete = mock.Mock()
        mock_delete_cgsnapshot = self.mock_object(self.library,
                                                  'delete_cgsnapshot')
        self.library.delete_group_snapshot(self.context, snap_dict,
                                           fallback_delete,
                                           share_server=fake.SHARE_SERVER)
        mock_delete_cgsnapshot.assert_not_called()
        fallback_delete.assert_called_once_with(self.context,
                                                snap_dict,
                                                share_server=fake.SHARE_SERVER)

    def test_create_group_from_snapshot_cg(self):
        share_group = mock.Mock()
        share_group.consistent_snapshot_support = 'host'
        snap_dict = {'share_group': share_group}
        fallback_create = mock.Mock()
        mock_create_cg_from_snapshot = self.mock_object(
            self.library, 'create_consistency_group_from_cgsnapshot')
        self.library.create_group_from_snapshot(self.context, share_group,
                                                snap_dict, fallback_create,
                                                share_server=fake.SHARE_SERVER)
        mock_create_cg_from_snapshot.assert_called_once_with(
            self.context, share_group, snap_dict,
            share_server=fake.SHARE_SERVER)
        fallback_create.assert_not_called()

    @ddt.data('pool', None, 'fake')
    def test_create_group_from_snapshot_fallback(self, css):
        share_group = mock.Mock()
        share_group.consistent_snapshot_support = css
        snap_dict = {'share_group': share_group}
        fallback_create = mock.Mock()
        mock_create_cg_from_snapshot = self.mock_object(
            self.library, 'create_consistency_group_from_cgsnapshot')
        self.library.create_group_from_snapshot(self.context, share_group,
                                                snap_dict, fallback_create,
                                                share_server=fake.SHARE_SERVER)
        mock_create_cg_from_snapshot.assert_not_called()
        fallback_create.assert_called_once_with(self.context, share_group,
                                                snap_dict,
                                                share_server=fake.SHARE_SERVER)
