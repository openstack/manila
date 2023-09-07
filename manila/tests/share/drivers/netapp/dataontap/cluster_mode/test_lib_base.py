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
from unittest import mock

import ddt
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

    def _mock_api_error(self, code='fake', message='fake'):
        return mock.Mock(side_effect=netapp_api.NaApiError(code=code,
                                                           message=message))

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
        self.mock_object(
            self.library._client, 'get_nfs_config_default',
            mock.Mock(return_value=fake.NFS_CONFIG_DEFAULT))
        self.mock_object(
            self.library, '_check_snaprestore_license',
            mock.Mock(return_value=True))
        self.mock_object(
            self.library,
            '_get_licenses',
            mock.Mock(return_value=fake.LICENSES))
        mock_get_api_client.features.TRANSFER_LIMIT_NFS_CONFIG = True

        self.library.do_setup(self.context)

        self.assertEqual(fake.LICENSES, self.library._licenses)
        mock_get_api_client.assert_called_once_with()
        (self.library._client.check_for_cluster_credentials.
            assert_called_once_with())
        (self.library._client.get_nfs_config_default.
            assert_called_once_with(
                list(self.library.NFS_CONFIG_EXTRA_SPECS_MAP.values())))
        self.assertEqual('fake_perf_library', self.library._perf_library)
        self.mock_object(self.library._client,
                         'check_for_cluster_credentials',
                         mock.Mock(return_value=True))
        self.mock_object(
            self.library, '_check_snaprestore_license',
            mock.Mock(return_value=True))
        mock_set_cluster_info = self.mock_object(
            self.library, '_set_cluster_info')
        self.library.do_setup(self.context)
        mock_set_cluster_info.assert_called_once()

    def test_set_cluster_info(self):
        self.library._client.is_nve_supported.return_value = True
        self.library._client.features.FLEXVOL_ENCRYPTION = True
        self.library._set_cluster_info()
        self.assertTrue(self.library._cluster_info['nve_support'])

    def test_check_for_setup_error(self):
        mock_start_periodic_tasks = self.mock_object(self.library,
                                                     '_start_periodic_tasks')
        self.library.check_for_setup_error()

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

    def test__get_backend_snapmirror_policy_name_svm(self):
        result = self.library._get_backend_snapmirror_policy_name_svm(
            fake.SERVER_ID)
        expected = 'snapmirror_policy_' + fake.SERVER_ID.replace('-', '_')

        self.assertEqual(expected, result)

    def test_get_aggregate_space_cluster_creds(self):

        self.library._have_cluster_creds = True
        self.mock_object(self.library._client,
                         'get_cluster_aggregate_capacities',
                         mock.Mock(return_value=fake.AGGREGATE_CAPACITIES))

        result = self.library._get_aggregate_space(fake.AGGREGATES)

        (self.library._client.get_cluster_aggregate_capacities.
            assert_called_once_with(fake.AGGREGATES))
        self.assertDictEqual(fake.AGGREGATE_CAPACITIES, result)

    def test_get_aggregate_space_no_cluster_creds(self):

        self.library._have_cluster_creds = False
        self.mock_object(self.library._client,
                         'get_vserver_aggregate_capacities',
                         mock.Mock(return_value=fake.AGGREGATE_CAPACITIES))

        result = self.library._get_aggregate_space(fake.AGGREGATES)

        (self.library._client.get_vserver_aggregate_capacities.
            assert_called_once_with(fake.AGGREGATES))
        self.assertDictEqual(fake.AGGREGATE_CAPACITIES, result)

    def test_check_snaprestore_license_admin_notfound(self):
        self.library._have_cluster_creds = True
        licenses = list(fake.LICENSES)
        licenses.remove('snaprestore')
        self.mock_object(self.client,
                         'get_licenses',
                         mock.Mock(return_value=licenses))
        result = self.library._check_snaprestore_license()
        self.assertIs(False, result)

    def test_check_snaprestore_license_admin_found(self):
        self.library._have_cluster_creds = True
        self.library._licenses = fake.LICENSES
        result = self.library._check_snaprestore_license()
        self.assertIs(True, result)

    def test_check_snaprestore_license_svm_scoped(self):
        self.library._have_cluster_creds = False
        self.mock_object(self.library._client,
                         'check_snaprestore_license',
                         mock.Mock(return_value=True))

        result = self.library._check_snaprestore_license()

        self.assertIs(True, result)

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

    def test_get_default_filter_function_flexgroup(self):
        mock_is_flexgroup = self.mock_object(
            self.library, '_is_flexgroup_pool',
            mock.Mock(return_value=True))
        mock_get_min = self.mock_object(
            self.library, '_get_minimum_flexgroup_size',
            mock.Mock(return_value=self.library.FLEXGROUP_MIN_SIZE_PER_AGGR))

        result = self.library.get_default_filter_function(pool=fake.POOL_NAME)

        expected_filer = (self.library.DEFAULT_FLEXGROUP_FILTER_FUNCTION %
                          self.library.FLEXGROUP_MIN_SIZE_PER_AGGR)
        self.assertEqual(expected_filer, result)
        mock_is_flexgroup.assert_called_once_with(fake.POOL_NAME)
        mock_get_min.assert_called_once_with(fake.POOL_NAME)

    def test_get_default_goodness_function(self):

        result = self.library.get_default_goodness_function()

        self.assertEqual(self.library.DEFAULT_GOODNESS_FUNCTION, result)

    @ddt.data(
        {'replication': True, 'flexgroup': False},
        {'replication': True, 'flexgroup': True},
        {'replication': False, 'flexgroup': False},
        {'replication': False, 'flexgroup': True},
    )
    @ddt.unpack
    def test_get_share_stats(self, replication, flexgroup):

        if replication:
            self.library.configuration.replication_domain = "fake_domain"
        if flexgroup:
            self.library._flexgroup_pools = {'pool': ['aggr']}

        mock_get_pools = self.mock_object(
            self.library, '_get_pools',
            mock.Mock(return_value=fake.POOLS))

        result = self.library.get_share_stats(get_filter_function='filter',
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
        if flexgroup:
            expected['share_group_stats']['consistent_snapshot_support'] = None
        if replication:
            expected['replication_type'] = ['dr', 'readable']
            expected['replication_domain'] = 'fake_domain'

        self.assertDictEqual(expected, result)
        mock_get_pools.assert_called_once_with(get_filter_function='filter',
                                               goodness_function='goodness')

    def test_get_share_server_pools(self):

        self.mock_object(self.library,
                         '_get_pools',
                         mock.Mock(return_value=fake.POOLS))
        self.library._cache_pool_status = na_utils.DataCache(60)

        result = self.library.get_share_server_pools(fake.SHARE_SERVER)

        self.assertListEqual(fake.POOLS, result)

    def test_get_pools(self):

        fake_total = 1.0
        fake_free = 1.0
        fake_used = 1.0
        fake_pool = copy.deepcopy(fake.POOLS)
        fake_pool.append(fake.FLEXGROUP_POOL)
        self.library._flexgroup_pools = fake.FLEXGROUP_POOL_OPT
        mock_find_aggr = self.mock_object(
            self.library, '_find_matching_aggregates',
            mock.Mock(return_value=fake.AGGREGATES))
        mock_get_flexgroup_aggr = self.mock_object(
            self.library, '_get_flexgroup_aggr_set',
            mock.Mock(return_value=fake.FLEXGROUP_AGGR_SET))
        mock_get_aggregate_space = self.mock_object(
            self.library, '_get_aggregate_space',
            mock.Mock(return_value=fake.AGGREGATE_CAPACITIES))
        mock_get_flexvol_space = self.mock_object(
            self.library, '_get_flexvol_pool_space',
            mock.Mock(return_value=(fake_total, fake_free, fake_used)))
        mock_get_pool = self.mock_object(
            self.library, '_get_pool',
            mock.Mock(side_effect=fake_pool))
        mock_get_flexgroup_space = self.mock_object(
            self.library, '_get_flexgroup_pool_space',
            mock.Mock(return_value=(fake_total, fake_free, fake_used)))
        mock_get_cluster_name = self.mock_object(
            self.library._client, 'get_cluster_name',
            mock.Mock(return_value='fake_cluster_name'))

        self.library._cache_pool_status = na_utils.DataCache(60)
        self.library._have_cluster_creds = True

        result = self.library._get_pools(
            get_filter_function=fake.fake_get_filter_function,
            goodness_function='goodness')

        self.assertListEqual(fake_pool, result)
        mock_find_aggr.assert_called_once_with()
        mock_get_flexgroup_aggr.assert_called_once_with()
        mock_get_aggregate_space.assert_called_once_with(set(fake.AGGREGATES))
        mock_get_flexvol_space.assert_has_calls([
            mock.call(fake.AGGREGATE_CAPACITIES, fake.AGGREGATES[0]),
            mock.call(fake.AGGREGATE_CAPACITIES, fake.AGGREGATES[1])])
        mock_get_flexgroup_space.assert_has_calls([
            mock.call(fake.AGGREGATE_CAPACITIES,
                      fake.FLEXGROUP_POOL_OPT[fake.FLEXGROUP_POOL_NAME])])
        mock_get_cluster_name.assert_called_once_with()
        mock_get_pool.assert_has_calls([
            mock.call(fake.AGGREGATES[0], fake_total, fake_free, fake_used),
            mock.call(fake.AGGREGATES[1], fake_total, fake_free, fake_used),
            mock.call(fake.FLEXGROUP_POOL_NAME, fake_total, fake_free,
                      fake_used)])

    def test_get_pool_vserver_creds(self):

        fake_pool = fake.POOLS_VSERVER_CREDS[0]
        self.library._have_cluster_creds = False
        self.library._revert_to_snapshot_support = True
        self.library._cluster_info = fake.CLUSTER_INFO
        self.library._ssc_stats = fake.SSC_INFO_VSERVER_CREDS
        self.library._perf_library.get_node_utilization_for_pool = (
            mock.Mock(return_value=50.0))

        result = self.library._get_pool(
            fake_pool['pool_name'], fake_pool['total_capacity_gb'],
            fake_pool['free_capacity_gb'], fake_pool['allocated_capacity_gb'])

        self.assertEqual(fake_pool, result)

    def test_get_pool_cluster_creds(self):

        fake_pool = copy.deepcopy(fake.POOLS[0])
        fake_pool['filter_function'] = None
        fake_pool['goodness_function'] = None
        fake_pool['netapp_cluster_name'] = ''
        self.library._have_cluster_creds = True
        self.library._revert_to_snapshot_support = True
        self.library._cluster_info = fake.CLUSTER_INFO
        self.library._ssc_stats = fake.SSC_INFO
        self.library._perf_library.get_node_utilization_for_pool = (
            mock.Mock(return_value=30.0))

        result = self.library._get_pool(
            fake_pool['pool_name'], fake_pool['total_capacity_gb'],
            fake_pool['free_capacity_gb'], fake_pool['allocated_capacity_gb'])

        self.assertEqual(fake_pool, result)

    def test_get_flexvol_pool_space(self):

        total_gb, free_gb, used_gb = self.library._get_flexvol_pool_space(
            fake.AGGREGATE_CAPACITIES, fake.AGGREGATES[0])

        self.assertEqual(total_gb, fake.POOLS[0]['total_capacity_gb'])
        self.assertEqual(free_gb, fake.POOLS[0]['free_capacity_gb'])
        self.assertEqual(used_gb, fake.POOLS[0]['allocated_capacity_gb'])

    def test_get_flexgroup_pool_space(self):

        total_gb, free_gb, used_gb = self.library._get_flexgroup_pool_space(
            fake.AGGREGATE_CAPACITIES, fake.FLEXGROUP_POOL_AGGR)

        self.assertEqual(total_gb, fake.FLEXGROUP_POOL['total_capacity_gb'])
        self.assertEqual(free_gb, fake.FLEXGROUP_POOL['free_capacity_gb'])
        self.assertEqual(used_gb, fake.FLEXGROUP_POOL['allocated_capacity_gb'])

    @ddt.data(
        {'aggr_space': fake.AGGREGATE_CAPACITIES, 'aggr_pool': []},
        {'aggr_space': fake.AGGREGATE_CAPACITIES, 'aggr_pool': ['fake']},
        {'aggr_space': {fake.AGGREGATES[0]: {}},
         'aggr_pool': [fake.AGGREGATES[0]]})
    @ddt.unpack
    def test_get_flexgroup_pool_space_zero(self, aggr_space, aggr_pool):

        total_gb, free_gb, used_gb = self.library._get_flexgroup_pool_space(
            aggr_space, aggr_pool)

        self.assertEqual(total_gb, 0.0)
        self.assertEqual(free_gb, 0.0)
        self.assertEqual(used_gb, 0.0)

    def test_get_flexgroup_aggr_set(self):

        self.library._flexgroup_pools = fake.FLEXGROUP_POOL_OPT

        result = self.library._get_flexgroup_aggr_set()

        self.assertSetEqual(result, set(fake.FLEXGROUP_POOL_AGGR))

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

    @ddt.data(True, False)
    def test_get_pool_no_pool(self, is_flexgroup):

        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['host'] = '%(host)s@%(backend)s' % {
            'host': fake.HOST_NAME, 'backend': fake.BACKEND_NAME}
        self.mock_object(self.library,
                         '_get_flexgroup_pool_name',
                         mock.Mock(return_value=fake.POOL_NAME))
        if is_flexgroup:
            self.client.get_aggregate_for_volume.return_value = [
                fake.POOL_NAME]
        else:
            self.client.get_aggregate_for_volume.return_value = fake.POOL_NAME

        result = self.library.get_pool(fake_share)

        self.assertEqual(fake.POOL_NAME, result)
        self.assertTrue(self.client.get_aggregate_for_volume.called)
        self.assertEqual(is_flexgroup,
                         self.library._get_flexgroup_pool_name.called)

    @ddt.data(True, False)
    def test_get_pool_raises(self, is_flexgroup):

        fake_share = copy.deepcopy(fake.SHARE)
        fake_share['host'] = '%(host)s@%(backend)s' % {
            'host': fake.HOST_NAME, 'backend': fake.BACKEND_NAME}
        self.mock_object(self.library,
                         '_get_flexgroup_pool_name',
                         mock.Mock(return_value=None))
        if is_flexgroup:
            self.client.get_aggregate_for_volume.return_value = []
        else:
            self.client.get_aggregate_for_volume.return_value = None

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

    @ddt.data(None, fake.CG_SNAPSHOT_MEMBER_ID1)
    def test_create_share_from_snapshot(self, share_group_id):

        share = copy.deepcopy(fake.SHARE)
        share['source_share_group_snapshot_member_id'] = share_group_id
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
            share,
            fake.SNAPSHOT,
            share_server=fake.SHARE_SERVER,
            parent_share=share)

        mock_allocate_container_from_snapshot.assert_called_once_with(
            share,
            fake.SNAPSHOT,
            fake.VSERVER1,
            vserver_client)
        mock_create_export.assert_called_once_with(share,
                                                   fake.SHARE_SERVER,
                                                   fake.VSERVER1,
                                                   vserver_client)
        self.assertEqual('fake_export_location', result)

    def _setup_mocks_for_create_share_from_snapshot(
            self, allocate_attr=None, dest_cluster=fake.CLUSTER_NAME,
            is_flexgroup=False, flexgroup_error=False):
        class FakeDBObj(dict):
            def to_dict(self):
                return self

        if allocate_attr is None:
            allocate_attr = mock.Mock()

        self.src_vserver_client = mock.Mock()
        self.mock_dm_session = mock.Mock()
        self.fake_share = FakeDBObj(fake.SHARE)
        self.fake_share_server = FakeDBObj(fake.SHARE_SERVER)

        self.mock_dm_constr = self.mock_object(
            data_motion, "DataMotionSession",
            mock.Mock(return_value=self.mock_dm_session))
        self.mock_dm_backend = self.mock_object(
            self.mock_dm_session, 'get_backend_info_for_share',
            mock.Mock(return_value=(None,
                                    fake.VSERVER1, fake.BACKEND_NAME)))
        self.mock_dm_get_src_client = self.mock_object(
            data_motion, 'get_client_for_backend',
            mock.Mock(return_value=self.src_vserver_client))
        self.mock_get_src_cluster = self.mock_object(
            self.src_vserver_client, 'get_cluster_name',
            mock.Mock(return_value=fake.CLUSTER_NAME))
        self.dest_vserver_client = mock.Mock()
        self.mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER2, self.dest_vserver_client)))
        self.mock_get_dest_cluster = self.mock_object(
            self.dest_vserver_client, 'get_cluster_name',
            mock.Mock(return_value=dest_cluster))
        self.mock_extract_host = self.mock_object(
            share_utils, 'extract_host',
            mock.Mock(return_value=fake.POOL_NAME))
        self.mock_is_flexgroup_share = self.mock_object(
            self.library, '_is_flexgroup_share',
            mock.Mock(return_value=is_flexgroup))
        self.mock_is_flexgroup_pool = self.mock_object(
            self.library, '_is_flexgroup_pool',
            mock.Mock(return_value=(not is_flexgroup if flexgroup_error
                                    else is_flexgroup)))
        self.mock_get_aggregate_for_volume = self.mock_object(
            self.src_vserver_client, 'get_aggregate_for_volume',
            mock.Mock(return_value=[fake.POOL_NAME]))
        self.mock_get_flexgroup_aggregate_list = self.mock_object(
            self.library, '_get_flexgroup_aggregate_list',
            mock.Mock(return_value=[fake.POOL_NAME]))
        self.mock_allocate_container_from_snapshot = self.mock_object(
            self.library, '_allocate_container_from_snapshot', allocate_attr)
        self.mock_allocate_container = self.mock_object(
            self.library, '_allocate_container')
        self.mock_get_relationship_type = self.mock_object(
            na_utils, 'get_relationship_type',
            mock.Mock(return_value=(na_utils.EXTENDED_DATA_PROTECTION_TYPE
                                    if is_flexgroup
                                    else na_utils.DATA_PROTECTION_TYPE)))
        self.mock_dm_create_snapmirror = self.mock_object(
            self.mock_dm_session, 'create_snapmirror')
        self.mock_storage_update = self.mock_object(
            self.library.private_storage, 'update')
        self.mock_generate_uuid = self.mock_object(
            uuidutils, 'generate_uuid', mock.Mock(return_value=fake.SHARE_ID5))

        # Parent share on MANILA_HOST_2
        self.parent_share = copy.copy(fake.SHARE)
        self.parent_share['share_server'] = fake.SHARE_SERVER_2
        self.parent_share['host'] = fake.MANILA_HOST_NAME_2
        self.parent_share_server = {}
        ss_keys = ['id', 'identifier', 'backend_details', 'host']
        for key in ss_keys:
            self.parent_share_server[key] = (
                self.parent_share['share_server'].get(key, None))
        self.temp_src_share = {
            'id': self.fake_share['id'],
            'host': self.parent_share['host'],
            'share_server': self.parent_share_server or None
        }

    @ddt.data({'dest_cluster': fake.CLUSTER_NAME, 'is_flexgroup': False,
              'have_cluster_creds': False},
              {'dest_cluster': fake.CLUSTER_NAME, 'is_flexgroup': False,
              'have_cluster_creds': True},
              {'dest_cluster': fake.CLUSTER_NAME, 'is_flexgroup': True,
              'have_cluster_creds': False},
              {'dest_cluster': fake.CLUSTER_NAME_2, 'is_flexgroup': False,
              'have_cluster_creds': False},
              {'dest_cluster': fake.CLUSTER_NAME_2, 'is_flexgroup': False,
              'have_cluster_creds': True},
              )
    @ddt.unpack
    def test_create_share_from_snapshot_another_host(self, dest_cluster,
                                                     is_flexgroup,
                                                     have_cluster_creds):
        self.library._have_cluster_creds = have_cluster_creds
        self._setup_mocks_for_create_share_from_snapshot(
            dest_cluster=dest_cluster, is_flexgroup=is_flexgroup)
        mock_get_backend_shr_name = self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(return_value=fake.SHARE_NAME))
        result = self.library.create_share_from_snapshot(
            self.context,
            self.fake_share,
            fake.SNAPSHOT,
            share_server=self.fake_share_server,
            parent_share=self.parent_share)

        self.fake_share['share_server'] = self.fake_share_server

        self.mock_dm_constr.assert_called_once()
        self.mock_dm_backend.assert_called_once_with(self.parent_share)
        self.mock_dm_get_src_client.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1)

        self.mock_get_vserver.assert_called_once_with(self.fake_share_server)
        if have_cluster_creds:
            self.mock_get_dest_cluster.assert_called_once()
            self.mock_get_src_cluster.assert_called_once()
        else:
            self.mock_get_dest_cluster.assert_not_called()
            self.mock_get_src_cluster.assert_not_called()
        mock_get_backend_shr_name.assert_called_once()
        self.mock_is_flexgroup_share.assert_called_once()
        self.mock_is_flexgroup_pool.assert_called_once()
        self.assertEqual(is_flexgroup,
                         self.mock_get_aggregate_for_volume.called)
        self.assertEqual(is_flexgroup,
                         self.mock_get_flexgroup_aggregate_list.called)

        if (dest_cluster != fake.CLUSTER_NAME
                or is_flexgroup or not have_cluster_creds):
            temp_share = copy.deepcopy(self.fake_share)
            temp_share["id"] = fake.SHARE_ID5
            self.mock_allocate_container_from_snapshot.assert_called_once_with(
                temp_share, fake.SNAPSHOT, fake.VSERVER1,
                self.src_vserver_client, split=False, create_fpolicy=False)
            self.mock_allocate_container.assert_called_once_with(
                self.fake_share, fake.VSERVER2,
                self.dest_vserver_client, replica=True, set_qos=False)
            self.mock_dm_create_snapmirror.assert_called_once()
            self.temp_src_share['replica_state'] = (
                constants.REPLICA_STATE_ACTIVE)
            state = self.library.STATE_SNAPMIRROR_DATA_COPYING
        else:
            self.mock_allocate_container_from_snapshot.assert_called_once_with(
                self.fake_share, fake.SNAPSHOT, fake.VSERVER1,
                self.src_vserver_client, split=True)
            state = self.library.STATE_SPLITTING_VOLUME_CLONE

            self.temp_src_share['aggregate'] = ([fake.POOL_NAME]
                                                if is_flexgroup
                                                else fake.POOL_NAME)
            self.temp_src_share['internal_state'] = state
            self.temp_src_share['status'] = constants.STATUS_ACTIVE
            str_temp_src_share = json.dumps(self.temp_src_share)
            self.mock_storage_update.assert_called_once_with(
                self.fake_share['id'], {
                    'source_share': str_temp_src_share
                })
            expected_return = {'status':
                               constants.STATUS_CREATING_FROM_SNAPSHOT}
            self.assertEqual(expected_return, result)

    @ddt.data(True, False)
    def test_create_share_from_snapshot_another_host_driver_error(
            self, have_cluster_creds):
        self.library._have_cluster_creds = have_cluster_creds
        self._setup_mocks_for_create_share_from_snapshot(
            allocate_attr=mock.Mock(side_effect=exception.NetAppException))
        mock_delete_snapmirror = self.mock_object(
            self.mock_dm_session, 'delete_snapmirror')

        mock_delete_share = self.mock_object(
            self.library, '_delete_share')

        self.assertRaises(exception.NetAppException,
                          self.library.create_share_from_snapshot,
                          self.context,
                          self.fake_share,
                          fake.SNAPSHOT,
                          share_server=self.fake_share_server,
                          parent_share=self.parent_share)

        self.fake_share['share_server'] = self.fake_share_server

        self.mock_dm_constr.assert_called_once()
        self.mock_dm_backend.assert_called_once_with(self.parent_share)
        self.mock_dm_get_src_client.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1)
        self.mock_get_vserver.assert_called_once_with(self.fake_share_server)
        if have_cluster_creds:
            self.mock_get_dest_cluster.assert_called_once()
            self.mock_get_src_cluster.assert_called_once()
        else:
            self.mock_get_dest_cluster.assert_not_called()
            self.mock_get_src_cluster.assert_not_called()

        if have_cluster_creds:
            self.mock_allocate_container_from_snapshot.assert_called_once_with(
                self.fake_share, fake.SNAPSHOT, fake.VSERVER1,
                self.src_vserver_client, split=True)
        else:
            self.mock_generate_uuid.assert_called_once()
            temp_share = copy.deepcopy(self.fake_share)
            temp_share["id"] = fake.SHARE_ID5
            self.mock_allocate_container_from_snapshot.assert_called_once_with(
                temp_share, fake.SNAPSHOT, fake.VSERVER1,
                self.src_vserver_client, split=False, create_fpolicy=False)

        mock_delete_snapmirror.assert_called_once_with(
            self.temp_src_share, self.fake_share)

        mock_delete_share.assert_called_once_with(
            self.temp_src_share, fake.VSERVER1, self.src_vserver_client,
            remove_export=False)

    def test_create_share_from_snapshot_different_pool_types(self):

        self._setup_mocks_for_create_share_from_snapshot(
            dest_cluster=fake.CLUSTER_NAME_2, is_flexgroup=True,
            flexgroup_error=True)
        self.assertRaises(exception.NetAppException,
                          self.library.create_share_from_snapshot,
                          self.context,
                          self.fake_share,
                          fake.SNAPSHOT,
                          share_server=self.fake_share_server,
                          parent_share=self.parent_share)

    def test_create_share_from_snapshot_mismatch_flexgroup_pools_len(self):

        self._setup_mocks_for_create_share_from_snapshot(
            dest_cluster=fake.CLUSTER_NAME_2, is_flexgroup=True)
        self.mock_object(
            self.library, '_get_flexgroup_aggregate_list',
            mock.Mock(return_value=[]))
        self.library._is_flexgroup_auto = False
        self.assertRaises(exception.NetAppException,
                          self.library.create_share_from_snapshot,
                          self.context,
                          self.fake_share,
                          fake.SNAPSHOT,
                          share_server=self.fake_share_server,
                          parent_share=self.parent_share)

    def test__update_create_from_snapshot_status(self):
        fake_result = mock.Mock()
        mock_pvt_storage_get = self.mock_object(
            self.library.private_storage, 'get',
            mock.Mock(return_value=fake.SHARE))
        mock__create_continue = self.mock_object(
            self.library, '_create_from_snapshot_continue',
            mock.Mock(return_value=fake_result))

        result = self.library._update_create_from_snapshot_status(
            fake.SHARE, fake.SHARE_SERVER)

        mock_pvt_storage_get.assert_called_once_with(fake.SHARE['id'],
                                                     'source_share')
        mock__create_continue.assert_called_once_with(fake.SHARE,
                                                      fake.SHARE_SERVER)
        self.assertEqual(fake_result, result)

    def test__update_create_from_snapshot_status_missing_source_share(self):
        mock_pvt_storage_get = self.mock_object(
            self.library.private_storage, 'get',
            mock.Mock(return_value=None))
        expected_result = {'status': constants.STATUS_ERROR}
        result = self.library._update_create_from_snapshot_status(
            fake.SHARE, fake.SHARE_SERVER)
        mock_pvt_storage_get.assert_called_once_with(fake.SHARE['id'],
                                                     'source_share')
        self.assertEqual(expected_result, result)

    def test__update_create_from_snapshot_status_driver_error(self):
        fake_src_share = {
            'id': fake.SHARE['id'],
            'host': fake.SHARE['host'],
            'internal_state': 'fake_internal_state',
        }
        copy_fake_src_share = copy.deepcopy(fake_src_share)
        src_vserver_client = mock.Mock()
        mock_dm_session = mock.Mock()
        mock_pvt_storage_get = self.mock_object(
            self.library.private_storage, 'get',
            mock.Mock(return_value=json.dumps(copy_fake_src_share)))
        mock__create_continue = self.mock_object(
            self.library, '_create_from_snapshot_continue',
            mock.Mock(side_effect=exception.NetAppException))
        mock_dm_constr = self.mock_object(
            data_motion, "DataMotionSession",
            mock.Mock(return_value=mock_dm_session))
        mock_delete_snapmirror = self.mock_object(
            mock_dm_session, 'delete_snapmirror')
        mock_dm_backend = self.mock_object(
            mock_dm_session, 'get_backend_info_for_share',
            mock.Mock(return_value=(None,
                                    fake.VSERVER1, fake.BACKEND_NAME)))
        mock_dm_get_src_client = self.mock_object(
            data_motion, 'get_client_for_backend',
            mock.Mock(return_value=src_vserver_client))
        mock_get_backend_shr_name = self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(return_value=fake.SHARE_NAME))
        mock_share_exits = self.mock_object(
            self.library, '_share_exists',
            mock.Mock(return_value=True))
        mock_deallocate_container = self.mock_object(
            self.library, '_deallocate_container')
        mock_pvt_storage_delete = self.mock_object(
            self.library.private_storage, 'delete')
        mock_delete_policy = self.mock_object(self.library,
                                              '_delete_fpolicy_for_share')

        result = self.library._update_create_from_snapshot_status(
            fake.SHARE, fake.SHARE_SERVER)
        expected_result = {'status': constants.STATUS_ERROR}

        mock_pvt_storage_get.assert_called_once_with(fake.SHARE['id'],
                                                     'source_share')
        mock__create_continue.assert_called_once_with(fake.SHARE,
                                                      fake.SHARE_SERVER)
        mock_dm_constr.assert_called_once()
        mock_delete_snapmirror.assert_called_once_with(fake_src_share,
                                                       fake.SHARE)
        mock_dm_backend.assert_called_once_with(fake_src_share)
        mock_dm_get_src_client.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1)
        mock_get_backend_shr_name.assert_called_once_with(fake_src_share['id'])
        mock_share_exits.assert_called_once_with(fake.SHARE_NAME,
                                                 src_vserver_client)
        mock_deallocate_container.assert_called_once_with(fake.SHARE_NAME,
                                                          src_vserver_client)
        mock_pvt_storage_delete.assert_called_once_with(fake.SHARE['id'])
        mock_delete_policy.assert_called_once_with(fake_src_share,
                                                   fake.VSERVER1,
                                                   src_vserver_client)
        self.assertEqual(expected_result, result)

    def _setup_mocks_for_create_from_snapshot_continue(
            self, src_host=fake.MANILA_HOST_NAME,
            dest_host=fake.MANILA_HOST_NAME, split_completed_result=True,
            move_completed_result=True, share_internal_state='fake_state',
            replica_state='in_sync', is_flexgroup=False):
        self.fake_export_location = 'fake_export_location'
        self.fake_src_share = {
            'id': fake.SHARE['id'],
            'host': src_host,
            'aggregate': src_host.split('#')[1],
            'internal_state': share_internal_state,
        }
        self.copy_fake_src_share = copy.deepcopy(self.fake_src_share)
        dest_pool = dest_host.split('#')[1]
        self.src_vserver_client = mock.Mock()
        self.dest_vserver_client = mock.Mock()
        self.mock_dm_session = mock.Mock()

        self.mock_dm_constr = self.mock_object(
            data_motion, "DataMotionSession",
            mock.Mock(return_value=self.mock_dm_session))
        self.mock_pvt_storage_get = self.mock_object(
            self.library.private_storage, 'get',
            mock.Mock(return_value=json.dumps(self.copy_fake_src_share)))
        self.mock_dm_backend = self.mock_object(
            self.mock_dm_session, 'get_backend_info_for_share',
            mock.Mock(return_value=(None,
                                    fake.VSERVER1, fake.BACKEND_NAME)))
        self.mock_extract_host = self.mock_object(
            share_utils, 'extract_host',
            mock.Mock(return_value=dest_pool))
        self.mock_is_flexgroup_pool = self.mock_object(
            self.library, '_is_flexgroup_pool',
            mock.Mock(return_value=is_flexgroup))
        self.mock_get_flexgroup_aggregate_list = self.mock_object(
            self.library, '_get_flexgroup_aggregate_list',
            mock.Mock(return_value=dest_pool))
        self.mock_dm_get_src_client = self.mock_object(
            data_motion, 'get_client_for_backend',
            mock.Mock(return_value=self.src_vserver_client))
        self.mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER2, self.dest_vserver_client)))
        self.mock_split_completed = self.mock_object(
            self.library, '_check_volume_clone_split_completed',
            mock.Mock(return_value=split_completed_result))
        self.mock_rehost_vol = self.mock_object(
            self.library, '_rehost_and_mount_volume')
        self.mock_move_vol = self.mock_object(self.library,
                                              '_move_volume_after_splitting')
        self.mock_move_completed = self.mock_object(
            self.library, '_check_volume_move_completed',
            mock.Mock(return_value=move_completed_result))
        self.mock_update_rep_state = self.mock_object(
            self.library, 'update_replica_state',
            mock.Mock(return_value=replica_state)
        )
        self.mock_update_snapmirror = self.mock_object(
            self.mock_dm_session, 'update_snapmirror')
        self.mock_break_snapmirror = self.mock_object(
            self.mock_dm_session, 'break_snapmirror')
        self.mock_delete_snapmirror = self.mock_object(
            self.mock_dm_session, 'delete_snapmirror')
        self.mock_get_backend_shr_name = self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(return_value=fake.SHARE_NAME))
        self.mock__delete_share = self.mock_object(self.library,
                                                   '_delete_share')
        self.mock_set_vol_size_fixes = self.mock_object(
            self.dest_vserver_client, 'set_volume_filesys_size_fixed')
        self.mock_create_export = self.mock_object(
            self.library, '_create_export',
            mock.Mock(return_value=self.fake_export_location))
        self.mock_pvt_storage_update = self.mock_object(
            self.library.private_storage, 'update')
        self.mock_pvt_storage_delete = self.mock_object(
            self.library.private_storage, 'delete')
        self.mock_get_extra_specs_qos = self.mock_object(
            share_types, 'get_extra_specs_from_share',
            mock.Mock(return_value=fake.EXTRA_SPEC_WITH_QOS))
        self.mock__get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options',
            mock.Mock(return_value=copy.deepcopy(fake.PROVISIONING_OPTIONS))
        )
        self.mock_modify_create_qos = self.mock_object(
            self.library, '_modify_or_create_qos_for_existing_share',
            mock.Mock(return_value=fake.QOS_POLICY_GROUP_NAME))
        self.mock_modify_vol = self.mock_object(self.dest_vserver_client,
                                                'modify_volume')
        self.mock_get_backend_qos_name = self.mock_object(
            self.library, '_get_backend_qos_policy_group_name',
            mock.Mock(return_value=fake.QOS_POLICY_GROUP_NAME))
        self.mock_mark_qos_deletion = self.mock_object(
            self.src_vserver_client, 'mark_qos_policy_group_for_deletion')

    @ddt.data(fake.MANILA_HOST_NAME, fake.MANILA_HOST_NAME_2)
    def test__create_from_snapshot_continue_state_splitting(self, src_host):
        self._setup_mocks_for_create_from_snapshot_continue(
            src_host=src_host,
            share_internal_state=self.library.STATE_SPLITTING_VOLUME_CLONE)

        result = self.library._create_from_snapshot_continue(fake.SHARE,
                                                             fake.SHARE_SERVER)
        fake.SHARE['share_server'] = fake.SHARE_SERVER
        self.mock_pvt_storage_get.assert_called_once_with(fake.SHARE['id'],
                                                          'source_share')
        self.mock_dm_backend.assert_called_once_with(self.fake_src_share)
        self.mock_extract_host.assert_has_calls([
            mock.call(fake.SHARE['host'], level='pool')])
        self.mock_dm_get_src_client.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1)
        self.mock_get_vserver.assert_called_once_with(fake.SHARE_SERVER)
        self.mock_split_completed.assert_called_once_with(
            self.fake_src_share, self.src_vserver_client)
        self.mock_get_backend_qos_name.assert_called_once_with(fake.SHARE_ID)
        self.mock_mark_qos_deletion.assert_called_once_with(
            fake.QOS_POLICY_GROUP_NAME)
        self.mock_rehost_vol.assert_called_once_with(
            fake.SHARE, fake.VSERVER1, self.src_vserver_client,
            fake.VSERVER2, self.dest_vserver_client)
        if src_host != fake.MANILA_HOST_NAME:
            expected_result = {
                'status': constants.STATUS_CREATING_FROM_SNAPSHOT
            }
            self.mock_move_vol.assert_called_once_with(
                self.fake_src_share, fake.SHARE, fake.SHARE_SERVER,
                cutover_action='defer')
            self.fake_src_share['internal_state'] = (
                self.library.STATE_MOVING_VOLUME)
            self.mock_pvt_storage_update.assert_called_once_with(
                fake.SHARE['id'],
                {'source_share': json.dumps(self.fake_src_share)}
            )
            self.assertEqual(expected_result, result)
        else:
            self.mock_get_extra_specs_qos.assert_called_once_with(fake.SHARE)
            self.mock__get_provisioning_opts.assert_called_once_with(
                fake.EXTRA_SPEC_WITH_QOS)
            self.mock_modify_create_qos.assert_called_once_with(
                fake.SHARE, fake.EXTRA_SPEC_WITH_QOS, fake.VSERVER2,
                self.dest_vserver_client)
            self.mock_get_backend_shr_name.assert_called_once_with(
                fake.SHARE_ID)
            self.mock_modify_vol.assert_called_once_with(
                fake.POOL_NAME, fake.SHARE_NAME,
                **fake.PROVISIONING_OPTIONS_WITH_QOS)
            self.mock_pvt_storage_delete.assert_called_once_with(
                fake.SHARE['id'])
            self.mock_create_export.assert_called_once_with(
                fake.SHARE, fake.SHARE_SERVER, fake.VSERVER2,
                self.dest_vserver_client, clear_current_export_policy=False)
            expected_result = {
                'status': constants.STATUS_AVAILABLE,
                'export_locations': self.fake_export_location,
            }
            self.assertEqual(expected_result, result)

    @ddt.data(True, False)
    def test__create_from_snapshot_continue_state_moving(self, move_completed):
        self._setup_mocks_for_create_from_snapshot_continue(
            share_internal_state=self.library.STATE_MOVING_VOLUME,
            move_completed_result=move_completed)

        result = self.library._create_from_snapshot_continue(fake.SHARE,
                                                             fake.SHARE_SERVER)
        expect_result = {
            'status': constants.STATUS_CREATING_FROM_SNAPSHOT
        }
        fake.SHARE['share_server'] = fake.SHARE_SERVER
        self.mock_pvt_storage_get.assert_called_once_with(fake.SHARE['id'],
                                                          'source_share')
        self.mock_dm_backend.assert_called_once_with(self.fake_src_share)
        self.mock_extract_host.assert_has_calls([
            mock.call(fake.SHARE['host'], level='pool'),
        ])
        self.mock_dm_get_src_client.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1)
        self.mock_get_vserver.assert_called_once_with(fake.SHARE_SERVER)

        self.mock_move_completed.assert_called_once_with(
            fake.SHARE, fake.SHARE_SERVER)
        if move_completed:
            expect_result['status'] = constants.STATUS_AVAILABLE
            self.mock_pvt_storage_delete.assert_called_once_with(
                fake.SHARE['id'])
            self.mock_create_export.assert_called_once_with(
                fake.SHARE, fake.SHARE_SERVER, fake.VSERVER2,
                self.dest_vserver_client, clear_current_export_policy=False)
            expect_result['export_locations'] = self.fake_export_location
            self.assertEqual(expect_result, result)
        else:
            self.mock_pvt_storage_update.assert_called_once_with(
                fake.SHARE['id'],
                {'source_share': json.dumps(self.fake_src_share)}
            )
            self.assertEqual(expect_result, result)

    @ddt.data({'replica_state': 'in_sync', 'is_flexgroup': False},
              {'replica_state': 'out_of_sync', 'is_flexgroup': False},
              {'replica_state': 'out_of_sync', 'is_flexgroup': True})
    @ddt.unpack
    def test__create_from_snapshot_continue_state_snapmirror(self,
                                                             replica_state,
                                                             is_flexgroup):
        self._setup_mocks_for_create_from_snapshot_continue(
            share_internal_state=self.library.STATE_SNAPMIRROR_DATA_COPYING,
            replica_state=replica_state, is_flexgroup=is_flexgroup)

        result = self.library._create_from_snapshot_continue(fake.SHARE,
                                                             fake.SHARE_SERVER)
        expect_result = {
            'status': constants.STATUS_CREATING_FROM_SNAPSHOT
        }
        fake.SHARE['share_server'] = fake.SHARE_SERVER
        self.mock_pvt_storage_get.assert_called_once_with(fake.SHARE['id'],
                                                          'source_share')
        self.mock_dm_backend.assert_called_once_with(self.fake_src_share)
        self.mock_extract_host.assert_has_calls([
            mock.call(fake.SHARE['host'], level='pool')])
        self.mock_dm_get_src_client.assert_called_once_with(
            fake.BACKEND_NAME, vserver_name=fake.VSERVER1)
        self.mock_get_vserver.assert_called_once_with(fake.SHARE_SERVER)

        self.mock_update_rep_state.assert_called_once_with(
            None, [self.fake_src_share], fake.SHARE, [], [], fake.SHARE_SERVER,
            replication=False
        )
        self.assertEqual(is_flexgroup,
                         self.mock_get_flexgroup_aggregate_list.called)
        if replica_state == constants.REPLICA_STATE_IN_SYNC:
            self.mock_update_snapmirror.assert_called_once_with(
                self.fake_src_share, fake.SHARE)
            self.mock_break_snapmirror.assert_called_once_with(
                self.fake_src_share, fake.SHARE)
            self.mock_delete_snapmirror.assert_called_once_with(
                self.fake_src_share, fake.SHARE)
            self.mock_get_backend_shr_name.assert_has_calls(
                [mock.call(self.fake_src_share['id']),
                 mock.call(fake.SHARE_ID)])
            self.mock__delete_share.assert_called_once_with(
                self.fake_src_share, fake.VSERVER1, self.src_vserver_client,
                remove_export=False)
            self.mock_set_vol_size_fixes.assert_called_once_with(
                fake.SHARE_NAME, filesys_size_fixed=False)
            self.mock_get_extra_specs_qos.assert_called_once_with(fake.SHARE)
            self.mock__get_provisioning_opts.assert_called_once_with(
                fake.EXTRA_SPEC_WITH_QOS)
            self.mock_modify_create_qos.assert_called_once_with(
                fake.SHARE, fake.EXTRA_SPEC_WITH_QOS, fake.VSERVER2,
                self.dest_vserver_client)
            self.mock_modify_vol.assert_called_once_with(
                fake.POOL_NAME, fake.SHARE_NAME,
                **fake.PROVISIONING_OPTIONS_WITH_QOS)
            expect_result['status'] = constants.STATUS_AVAILABLE
            self.mock_pvt_storage_delete.assert_called_once_with(
                fake.SHARE['id'])
            self.mock_create_export.assert_called_once_with(
                fake.SHARE, fake.SHARE_SERVER, fake.VSERVER2,
                self.dest_vserver_client, clear_current_export_policy=False)
            expect_result['export_locations'] = self.fake_export_location
            self.assertEqual(expect_result, result)
        elif replica_state not in [constants.STATUS_ERROR, None]:
            self.mock_pvt_storage_update.assert_called_once_with(
                fake.SHARE['id'],
                {'source_share': json.dumps(self.fake_src_share)}
            )
            self.assertEqual(expect_result, result)

    def test__create_from_snapshot_continue_state_unknown(self):
        self._setup_mocks_for_create_from_snapshot_continue(
            share_internal_state='unknown_state')

        self.assertRaises(exception.NetAppException,
                          self.library._create_from_snapshot_continue,
                          fake.SHARE,
                          fake.SHARE_SERVER)

        self.mock_pvt_storage_delete.assert_called_once_with(fake.SHARE_ID)

    @ddt.data({'hide_snapdir': False, 'create_fpolicy': True, 'is_fg': True},
              {'hide_snapdir': True, 'create_fpolicy': False, 'is_fg': True},
              {'hide_snapdir': False, 'create_fpolicy': True, 'is_fg': False},
              {'hide_snapdir': True, 'create_fpolicy': False, 'is_fg': False})
    @ddt.unpack
    def test_allocate_container(self, hide_snapdir, create_fpolicy, is_fg):

        provisioning_options = copy.deepcopy(
            fake.PROVISIONING_OPTIONS_WITH_FPOLICY)
        provisioning_options['hide_snapdir'] = hide_snapdir
        self.mock_object(self.library, '_get_backend_share_name', mock.Mock(
            return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value=fake.POOL_NAME))
        mock_get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options_for_share',
            mock.Mock(return_value=provisioning_options))
        mock_create_fpolicy = self.mock_object(
            self.library, '_create_fpolicy_for_share')
        self.mock_object(
            self.library, '_is_flexgroup_pool', mock.Mock(return_value=is_fg))
        mock_create_flexgroup = self.mock_object(self.library,
                                                 '_create_flexgroup_share')
        mock_get_aggr_flexgroup = self.mock_object(
            self.library, '_get_flexgroup_aggregate_list',
            mock.Mock(return_value=[fake.AGGREGATE]))
        vserver_client = mock.Mock()

        self.library._allocate_container(fake.SHARE_INSTANCE,
                                         fake.VSERVER1,
                                         vserver_client,
                                         create_fpolicy=create_fpolicy)

        mock_get_provisioning_opts.assert_called_once_with(
            fake.SHARE_INSTANCE, fake.VSERVER1, vserver_client=vserver_client,
            set_qos=True)

        if is_fg:
            mock_get_aggr_flexgroup.assert_called_once_with(fake.POOL_NAME)
            mock_create_flexgroup.assert_called_once_with(
                vserver_client, [fake.AGGREGATE], fake.SHARE_NAME,
                fake.SHARE['size'], 8, **provisioning_options)
        else:
            mock_get_aggr_flexgroup.assert_not_called()
            vserver_client.create_volume.assert_called_once_with(
                fake.POOL_NAME, fake.SHARE_NAME, fake.SHARE['size'],
                snapshot_reserve=8, **provisioning_options)

        if hide_snapdir:
            vserver_client.set_volume_snapdir_access.assert_called_once_with(
                fake.SHARE_NAME, hide_snapdir)
        else:
            vserver_client.set_volume_snapdir_access.assert_not_called()

        if create_fpolicy:
            mock_create_fpolicy.assert_called_once_with(
                fake.SHARE_INSTANCE, fake.VSERVER1, vserver_client,
                **provisioning_options)
        else:
            mock_create_fpolicy.assert_not_called()

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

        self.library._allocate_container(fake.SHARE_INSTANCE, fake.VSERVER1,
                                         vserver_client, replica=True)

        mock_get_provisioning_opts.assert_called_once_with(
            fake.SHARE_INSTANCE, fake.VSERVER1, vserver_client=vserver_client,
            set_qos=True)

        vserver_client.create_volume.assert_called_once_with(
            fake.POOL_NAME, fake.SHARE_NAME, fake.SHARE['size'],
            thin_provisioned=True, snapshot_policy='default',
            language='en-US', dedup_enabled=True, split=True,
            compression_enabled=False, max_files=5000, encrypt=False,
            snapshot_reserve=8, volume_type='dp',
            adaptive_qos_policy_group=None)

    def test_allocate_container_no_pool_name(self):
        self.mock_object(self.library, '_get_backend_share_name', mock.Mock(
            return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value=None))
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_get_provisioning_options')
        vserver_client = mock.Mock()

        self.assertRaises(exception.InvalidHost,
                          self.library._allocate_container,
                          fake.SHARE_INSTANCE, fake.VSERVER1, vserver_client)

        self.library._get_backend_share_name.assert_called_once_with(
            fake.SHARE_INSTANCE['id'])
        share_utils.extract_host.assert_called_once_with(
            fake.SHARE_INSTANCE['host'], level='pool')
        self.assertEqual(0,
                         self.library._check_extra_specs_validity.call_count)
        self.assertEqual(0, self.library._get_provisioning_options.call_count)

    @ddt.data(None, 1000)
    def test_create_flexgroup_share(self, max_files):
        self.library.configuration.netapp_flexgroup_volume_online_timeout = 2
        vserver_client = mock.Mock()
        vserver_client.get_job_state.return_value = "success"
        mock_wait_for_start = self.mock_object(
            self.library, 'wait_for_start_create_flexgroup',
            mock.Mock(return_value={'jobid': fake.JOB_ID, 'error-code': None}))
        mock_wait_for_flexgroup_deployment = self.mock_object(
            self.library, 'wait_for_flexgroup_deployment')
        aggr_list = [fake.AGGREGATE]

        self.library._create_flexgroup_share(vserver_client, aggr_list,
                                             fake.SHARE_NAME, 100, 10,
                                             max_files=max_files)

        start_timeout = (self.library.configuration.
                         netapp_flexgroup_aggregate_not_busy_timeout)
        mock_wait_for_start.assert_called_once_with(
            start_timeout, vserver_client, aggr_list, fake.SHARE_NAME, 100, 10)
        mock_wait_for_flexgroup_deployment.assert_called_once_with(
            vserver_client, fake.JOB_ID, 2)
        (vserver_client.update_volume_efficiency_attributes.
            assert_called_once_with(fake.SHARE_NAME, False, False,
                                    is_flexgroup=True))
        if max_files:
            vserver_client.set_volume_max_files.assert_called_once_with(
                fake.SHARE_NAME, max_files)
        else:
            self.assertFalse(vserver_client.set_volume_max_files.called)

    @ddt.data(
        {'jobid': fake.JOB_ID, 'error-code': 'fake', 'error-message': 'fake'},
        {'jobid': None, 'error-code': None, 'error-message': 'fake'})
    def test_create_flexgroup_share_raise_error_job(self, job):
        vserver_client = mock.Mock()
        self.mock_object(self.library, 'wait_for_start_create_flexgroup',
                         mock.Mock(return_value=job))
        aggr_list = [fake.AGGREGATE]

        self.assertRaises(
            exception.NetAppException, self.library._create_flexgroup_share,
            vserver_client, aggr_list, fake.SHARE_NAME, 100, 10)

    def test_wait_for_start_create_flexgroup(self):
        vserver_client = mock.Mock()
        job = {'jobid': fake.JOB_ID, 'error-code': None}
        vserver_client.create_volume_async.return_value = job
        aggr_list = [fake.AGGREGATE]

        result = self.library.wait_for_start_create_flexgroup(
            20, vserver_client, aggr_list, fake.SHARE_NAME, 1, 10)

        self.assertEqual(job, result)
        vserver_client.create_volume_async.assert_called_once_with(
            aggr_list, fake.SHARE_NAME, 1, is_flexgroup=True,
            snapshot_reserve=10,
            auto_provisioned=self.library._is_flexgroup_auto)

    def test_wait_for_start_create_flexgroup_timeout(self):
        vserver_client = mock.Mock()
        vserver_client.create_volume_async.side_effect = (
            netapp_api.NaApiError(code=netapp_api.EAPIERROR,
                                  message="try the command again"))
        aggr_list = [fake.AGGREGATE]

        self.assertRaises(
            exception.NetAppException,
            self.library.wait_for_start_create_flexgroup, 10,
            vserver_client, aggr_list, fake.SHARE_NAME, 1, 10)

    def test_wait_for_flexgroup_deployment(self):
        vserver_client = mock.Mock()
        vserver_client.get_job_state.return_value = 'success'

        result = self.library.wait_for_flexgroup_deployment(
            vserver_client, fake.JOB_ID, 20)

        self.assertIsNone(result)
        vserver_client.get_job_state.assert_called_once_with(fake.JOB_ID)

    def test_wait_for_flexgroup_deployment_timeout(self):
        vserver_client = mock.Mock()
        vserver_client.get_job_state.return_value = 'queued'

        self.assertRaises(
            exception.NetAppException,
            self.library.wait_for_flexgroup_deployment,
            vserver_client, fake.JOB_ID, 10)

    @ddt.data('failure', 'error')
    def test_wai_for_flexgroup_deployment_job_error(self, error_state):
        vserver_client = mock.Mock()
        vserver_client.get_job_state.return_value = error_state

        self.assertRaises(
            exception.NetAppException,
            self.library.wait_for_flexgroup_deployment,
            vserver_client, fake.JOB_ID, 10)

    def test_check_extra_specs_validity(self):
        boolean_extra_spec_keys = list(
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)
        mock_bool_check = self.mock_object(
            self.library, '_check_boolean_extra_specs_validity')
        mock_string_check = self.mock_object(
            self.library, '_check_string_extra_specs_validity')

        self.library._check_extra_specs_validity(
            fake.SHARE_INSTANCE, fake.EXTRA_SPEC)

        mock_bool_check.assert_called_once_with(
            fake.SHARE_INSTANCE, fake.EXTRA_SPEC, boolean_extra_spec_keys)
        mock_string_check.assert_called_once_with(
            fake.SHARE_INSTANCE, fake.EXTRA_SPEC)

    def test_check_extra_specs_validity_empty_spec(self):
        result = self.library._check_extra_specs_validity(
            fake.SHARE_INSTANCE, fake.EMPTY_EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_extra_specs_validity_invalid_value(self):
        self.assertRaises(
            exception.Invalid, self.library._check_extra_specs_validity,
            fake.SHARE_INSTANCE, fake.INVALID_EXTRA_SPEC)

    def test_check_string_extra_specs_validity(self):
        result = self.library._check_string_extra_specs_validity(
            fake.SHARE_INSTANCE, fake.EXTRA_SPEC_WITH_FPOLICY)

        self.assertIsNone(result)

    def test_check_string_extra_specs_validity_empty_spec(self):
        result = self.library._check_string_extra_specs_validity(
            fake.SHARE_INSTANCE, fake.EMPTY_EXTRA_SPEC)

        self.assertIsNone(result)

    def test_check_string_extra_specs_validity_invalid_value(self):
        self.assertRaises(
            exception.NetAppException,
            self.library._check_string_extra_specs_validity,
            fake.SHARE_INSTANCE, fake.INVALID_MAX_FILE_EXTRA_SPEC)

    def test_check_boolean_extra_specs_validity_invalid_value(self):
        self.assertRaises(
            exception.Invalid,
            self.library._check_boolean_extra_specs_validity,
            fake.SHARE_INSTANCE, fake.INVALID_EXTRA_SPEC,
            list(self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP))

    def test_check_extra_specs_validity_invalid_combination(self):
        self.assertRaises(
            exception.Invalid,
            self.library._check_boolean_extra_specs_validity,
            fake.SHARE_INSTANCE, fake.INVALID_EXTRA_SPEC_COMBO,
            list(self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP))

    @ddt.data({'extra_specs': fake.EXTRA_SPEC, 'set_qos': True},
              {'extra_specs': fake.EXTRA_SPEC_WITH_QOS, 'set_qos': False},
              {'extra_specs': fake.EXTRA_SPEC, 'set_qos': True},
              {'extra_specs': fake.EXTRA_SPEC_WITH_QOS, 'set_qos': False})
    @ddt.unpack
    def test_get_provisioning_options_for_share(self, extra_specs, set_qos):

        qos = True if fake.QOS_EXTRA_SPEC in extra_specs else False
        vserver_client = mock.Mock()
        self.library._have_cluster_creds = True
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
            fake.SHARE_INSTANCE, fake.VSERVER1, vserver_client=vserver_client,
            set_qos=set_qos)

        if qos and not set_qos:
            expected_provisioning_opts = fake.PROVISIONING_OPTIONS
            self.assertFalse(mock_create_qos_policy_group.called)
        else:
            expected_provisioning_opts = fake.PROVISIONING_OPTIONS_WITH_QOS
            mock_create_qos_policy_group.assert_called_once_with(
                fake.SHARE_INSTANCE, fake.VSERVER1,
                {fake.QOS_NORMALIZED_SPEC: 3000}, vserver_client)

        self.assertEqual(expected_provisioning_opts, result)
        mock_get_extra_specs_from_share.assert_called_once_with(
            fake.SHARE_INSTANCE)
        mock_remap_standard_boolean_extra_specs.assert_called_once_with(
            extra_specs)
        mock_check_extra_specs_validity.assert_called_once_with(
            fake.SHARE_INSTANCE, extra_specs)
        mock_get_provisioning_options.assert_called_once_with(extra_specs)
        mock_get_normalized_qos_specs.assert_called_once_with(extra_specs)

    def test_get_provisioning_options_for_share_qos_conflict(self):
        vserver_client = mock.Mock()
        extra_specs = fake.EXTRA_SPEC_WITH_QOS
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
            mock.Mock(return_value=fake.PROVISIONING_OPTS_WITH_ADAPT_QOS))
        mock_get_normalized_qos_specs = self.mock_object(
            self.library, '_get_normalized_qos_specs',
            mock.Mock(return_value={fake.QOS_NORMALIZED_SPEC: 3000}))

        self.assertRaises(exception.NetAppException,
                          self.library._get_provisioning_options_for_share,
                          fake.SHARE_INSTANCE, fake.VSERVER1,
                          vserver_client=vserver_client,
                          set_qos=True)

        mock_get_extra_specs_from_share.assert_called_once_with(
            fake.SHARE_INSTANCE)
        mock_remap_standard_boolean_extra_specs.assert_called_once_with(
            extra_specs)
        mock_check_extra_specs_validity.assert_called_once_with(
            fake.SHARE_INSTANCE, extra_specs)
        mock_get_provisioning_options.assert_called_once_with(extra_specs)
        mock_get_normalized_qos_specs.assert_called_once_with(extra_specs)

    def test_get_provisioning_options_implicit_false(self):
        result = self.library._get_provisioning_options(
            fake.EMPTY_EXTRA_SPEC)

        expected = {
            'adaptive_qos_policy_group': None,
            'language': None,
            'max_files': None,
            'snapshot_policy': None,
            'thin_provisioned': False,
            'compression_enabled': False,
            'dedup_enabled': False,
            'split': False,
            'encrypt': False,
            'hide_snapdir': False,
            'fpolicy_extensions_to_exclude': None,
            'fpolicy_extensions_to_include': None,
            'fpolicy_file_operations': None,
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
            'hide_snapdir': False,
        }

        result = self.library._get_boolean_provisioning_options(
            fake.EMPTY_EXTRA_SPEC,
            self.library.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(expected, result)

    def test_get_string_provisioning_options(self):
        result = self.library.get_string_provisioning_options(
            fake.STRING_EXTRA_SPEC,
            self.library.STRING_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_STRING, result)

    def test_get_string_provisioning_options_missing_spec(self):
        result = self.library.get_string_provisioning_options(
            fake.SHORT_STRING_EXTRA_SPEC,
            self.library.STRING_QUALIFIED_EXTRA_SPECS_MAP)

        self.assertEqual(fake.PROVISIONING_OPTIONS_STRING_MISSING_SPECS,
                         result)

    def test_get_string_provisioning_options_implicit_false(self):
        result = self.library.get_string_provisioning_options(
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
            self.assertDictEqual(
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

        self.assertDictEqual(expected_normalized_spec, qos_specs)
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

    def test__check_fpolicy_file_operations(self):
        result = self.library._check_fpolicy_file_operations(
            fake.SHARE, fake.FPOLICY_FILE_OPERATIONS)

        self.assertIsNone(result)

    def test__check_fpolicy_file_operations_invalid_operation(self):
        invalid_ops = copy.deepcopy(fake.FPOLICY_FILE_OPERATIONS)
        invalid_ops += ',fake_op'

        self.assertRaises(exception.NetAppException,
                          self.library._check_fpolicy_file_operations,
                          fake.SHARE,
                          invalid_ops)

    def test_allocate_container_no_pool(self):

        vserver_client = mock.Mock()
        fake_share_inst = copy.deepcopy(fake.SHARE_INSTANCE)
        fake_share_inst['host'] = fake_share_inst['host'].split('#')[0]

        self.assertRaises(exception.InvalidHost,
                          self.library._allocate_container,
                          fake_share_inst,
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

    @ddt.data({'provider_location': None, 'size': 50, 'hide_snapdir': True,
               'split': None, 'create_fpolicy': False},
              {'provider_location': 'fake_location', 'size': 30,
               'hide_snapdir': False, 'split': True, 'create_fpolicy': True},
              {'provider_location': 'fake_location', 'size': 20,
               'hide_snapdir': True, 'split': False, 'create_fpolicy': True})
    @ddt.unpack
    def test_allocate_container_from_snapshot(
            self, provider_location, size, hide_snapdir, split,
            create_fpolicy):
        provisioning_options = copy.deepcopy(
            fake.PROVISIONING_OPTIONS_WITH_FPOLICY)
        provisioning_options['hide_snapdir'] = hide_snapdir
        mock_get_provisioning_opts = self.mock_object(
            self.library, '_get_provisioning_options_for_share',
            mock.Mock(return_value=provisioning_options))
        mock_create_fpolicy = self.mock_object(
            self.library, '_create_fpolicy_for_share')
        vserver = fake.VSERVER1
        vserver_client = mock.Mock()
        original_snapshot_size = 20

        fake_share_inst = copy.deepcopy(fake.SHARE_INSTANCE)
        fake_share_inst['size'] = size
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['provider_location'] = provider_location
        fake_snapshot['size'] = original_snapshot_size

        self.library._allocate_container_from_snapshot(
            fake_share_inst,
            fake_snapshot,
            vserver,
            vserver_client,
            create_fpolicy=create_fpolicy)

        share_name = self.library._get_backend_share_name(
            fake_share_inst['id'])
        parent_share_name = self.library._get_backend_share_name(
            fake_snapshot['share_id'])
        parent_snapshot_name = self.library._get_backend_snapshot_name(
            fake_snapshot['id']) if not provider_location else 'fake_location'
        mock_get_provisioning_opts.assert_called_once_with(
            fake_share_inst, fake.VSERVER1, vserver_client=vserver_client)
        vserver_client.create_volume_clone.assert_called_once_with(
            share_name, parent_share_name, parent_snapshot_name,
            **provisioning_options)
        if size > original_snapshot_size:
            vserver_client.set_volume_size.assert_called_once_with(
                share_name, size)
        else:
            vserver_client.set_volume_size.assert_not_called()

        if hide_snapdir:
            vserver_client.set_volume_snapdir_access.assert_called_once_with(
                fake.SHARE_INSTANCE_NAME, hide_snapdir)
        else:
            vserver_client.set_volume_snapdir_access.assert_not_called()

        if create_fpolicy:
            mock_create_fpolicy.assert_called_once_with(
                fake_share_inst, vserver, vserver_client,
                **provisioning_options)
        else:
            mock_create_fpolicy.assert_not_called()

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
        mock_delete_policy = self.mock_object(self.library,
                                              '_delete_fpolicy_for_share')

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
        mock_delete_policy.assert_called_once_with(fake.SHARE, fake.VSERVER1,
                                                   vserver_client)
        (vserver_client.mark_qos_policy_group_for_deletion
         .assert_called_once_with(qos_policy_name))
        self.assertEqual(0, lib_base.LOG.info.call_count)

    def test__delete_share_no_remove_qos_and_export(self):

        vserver_client = mock.Mock()
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=True))
        mock_remove_export = self.mock_object(self.library, '_remove_export')
        mock_deallocate_container = self.mock_object(self.library,
                                                     '_deallocate_container')
        mock_delete_policy = self.mock_object(self.library,
                                              '_delete_fpolicy_for_share')
        mock_get_backend_qos = self.mock_object(
            self.library, '_get_backend_qos_policy_group_name')
        mock_get_share_name = self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(return_value=fake.SHARE_NAME))

        self.library._delete_share(fake.SHARE,
                                   fake.VSERVER1,
                                   vserver_client,
                                   remove_export=False,
                                   remove_qos=False)

        mock_get_share_name.assert_called_once_with(fake.SHARE_ID)
        mock_delete_policy.assert_called_once_with(fake.SHARE, fake.VSERVER1,
                                                   vserver_client)
        mock_share_exists.assert_called_once_with(fake.SHARE_NAME,
                                                  vserver_client)

        mock_deallocate_container.assert_called_once_with(fake.SHARE_NAME,
                                                          vserver_client)
        mock_remove_export.assert_not_called()
        mock_get_backend_qos.assert_not_called()
        vserver_client.mark_qos_policy_group_for_deletion.assert_not_called()

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
        mock_delete_fpolicy = self.mock_object(self.library,
                                               '_delete_fpolicy_for_share')

        self.library.delete_share(self.context,
                                  fake.SHARE,
                                  share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(fake.SHARE['id'])
        mock_share_exists.assert_called_once_with(share_name, vserver_client)
        mock_delete_fpolicy.assert_called_once_with(fake.SHARE, fake.VSERVER1,
                                                    vserver_client)
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

    @ddt.data(None, fake.MANILA_HOST_NAME_2)
    def test_create_export(self, share_host):

        protocol_helper = mock.Mock()
        callback = (lambda export_address, export_path='fake_export_path':
                    ':'.join([export_address, export_path]))
        protocol_helper.create_share.return_value = callback
        expected_host = share_host if share_host else fake.SHARE['host']
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        self.mock_object(self.library,
                         '_is_flexgroup_pool', mock.Mock(return_value=False))
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
                                             vserver_client,
                                             share_host=share_host)

        self.assertEqual(fake.NFS_EXPORTS, result)
        mock_get_export_addresses_with_metadata.assert_called_once_with(
            fake.SHARE, fake.SHARE_SERVER, fake.LIFS, expected_host)
        protocol_helper.create_share.assert_called_once_with(
            fake.SHARE, fake.SHARE_NAME, clear_current_export_policy=True,
            ensure_share_already_exists=False, replica=False,
            is_flexgroup=False)

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

    @ddt.data(True, False)
    def test_get_export_addresses_with_metadata(self, is_flexgroup):

        self.mock_object(
            self.library, '_is_flexgroup_pool',
            mock.Mock(return_value=is_flexgroup))
        mock_get_aggr_flexgroup = self.mock_object(
            self.library, '_get_flexgroup_aggregate_list',
            mock.Mock(return_value=[fake.AGGREGATE]))
        mock_get_aggregate_node = self.mock_object(
            self.library, '_get_aggregate_node',
            mock.Mock(return_value=fake.CLUSTER_NODES[0]))
        mock_get_admin_addresses_for_share_server = self.mock_object(
            self.library, '_get_admin_addresses_for_share_server',
            mock.Mock(return_value=[fake.LIF_ADDRESSES[1]]))

        result = self.library._get_export_addresses_with_metadata(
            fake.SHARE, fake.SHARE_SERVER, fake.LIFS, fake.SHARE['host'])

        self.assertEqual(fake.INTERFACE_ADDRESSES_WITH_METADATA, result)
        mock_get_admin_addresses_for_share_server.assert_called_once_with(
            fake.SHARE_SERVER)
        if is_flexgroup:
            mock_get_aggr_flexgroup.assert_called_once_with(fake.POOL_NAME)
            mock_get_aggregate_node.assert_called_once_with(fake.AGGREGATE)
        else:
            mock_get_aggregate_node.assert_called_once_with(fake.POOL_NAME)

    def test_get_export_addresses_with_metadata_node_unknown(self):

        self.mock_object(
            self.library, '_is_flexgroup_pool', mock.Mock(return_value=False))
        mock_get_aggregate_node = self.mock_object(
            self.library, '_get_aggregate_node',
            mock.Mock(return_value=None))
        mock_get_admin_addresses_for_share_server = self.mock_object(
            self.library, '_get_admin_addresses_for_share_server',
            mock.Mock(return_value=[fake.LIF_ADDRESSES[1]]))

        result = self.library._get_export_addresses_with_metadata(
            fake.SHARE, fake.SHARE_SERVER, fake.LIFS, fake.SHARE['host'])

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
        mock_is_flexgroup_share = self.mock_object(
            self.library, '_is_flexgroup_share', mock.Mock(return_value=False))
        mock_delete_snapshot = self.mock_object(self.library,
                                                '_delete_snapshot')

        self.library.delete_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        share_name = self.library._get_backend_share_name(
            fake.SNAPSHOT['share_id'])
        snapshot_name = self.library._get_backend_snapshot_name(
            fake.SNAPSHOT['id'])
        mock_is_flexgroup_share.assert_called_once_with(vserver_client,
                                                        share_name)
        mock_delete_snapshot.assert_called_once_with(
            vserver_client, share_name, snapshot_name, is_flexgroup=False)

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
            share_name, fake_snapshot['provider_location'])

    @ddt.data(exception.InvalidInput(reason='fake_reason'),
              exception.VserverNotSpecified(),
              exception.VserverNotFound(vserver='fake_vserver'))
    def test_delete_snapshot_no_share_server(self, get_vserver_exception):

        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(side_effect=get_vserver_exception))
        mock_is_flexgroup_share = self.mock_object(
            self.library, '_is_flexgroup_share', mock.Mock(return_value=False))
        mock_delete_snapshot = self.mock_object(self.library,
                                                '_delete_snapshot')

        self.library.delete_snapshot(self.context,
                                     fake.SNAPSHOT,
                                     share_server=fake.SHARE_SERVER)

        self.assertFalse(mock_is_flexgroup_share.called)
        self.assertFalse(mock_delete_snapshot.called)

    def test_delete_snapshot_not_found(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_is_flexgroup_share = self.mock_object(
            self.library, '_is_flexgroup_share', mock.Mock(return_value=False))
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
        mock_is_flexgroup_share.assert_called_once_with(
            vserver_client, share_name)
        mock_delete_snapshot.assert_called_once_with(
            vserver_client, share_name, snapshot_name, is_flexgroup=False)

    def test_delete_snapshot_not_unique(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        mock_is_flexgroup_share = self.mock_object(
            self.library, '_is_flexgroup_share', mock.Mock(return_value=False))
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
        mock_is_flexgroup_share.assert_called_once_with(
            vserver_client, share_name)
        mock_delete_snapshot.assert_called_once_with(
            vserver_client, share_name, snapshot_name, is_flexgroup=False)

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

    @ddt.data(True, False)
    def test__delete_snapshot_busy_volume_clone(self, is_flexgroup):

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = (
            fake.CDOT_SNAPSHOT_BUSY_VOLUME_CLONE)
        vserver_client.get_clone_children_for_snapshot.return_value = (
            fake.CDOT_CLONE_CHILDREN)
        mock_is_flexgroup_share = self.mock_object(
            self.library, '_delete_busy_snapshot')

        self.library._delete_snapshot(vserver_client,
                                      fake.SHARE_NAME,
                                      fake.SNAPSHOT_NAME,
                                      is_flexgroup=is_flexgroup)

        self.assertFalse(vserver_client.delete_snapshot.called)
        vserver_client.get_clone_children_for_snapshot.assert_called_once_with(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)
        vserver_client.split_volume_clone.assert_has_calls([
            mock.call(fake.CDOT_CLONE_CHILD_1),
            mock.call(fake.CDOT_CLONE_CHILD_2),
        ])
        if is_flexgroup:
            mock_is_flexgroup_share.assert_called_once_with(
                vserver_client, fake.SHARE_NAME, fake.SNAPSHOT_NAME)
            vserver_client.soft_delete_snapshot.assert_not_called()
        else:
            mock_is_flexgroup_share.assert_not_called()
            vserver_client.soft_delete_snapshot.assert_called_once_with(
                fake.SHARE_NAME, fake.SNAPSHOT_NAME)

    def test__delete_snapshot_busy_snapmirror(self):

        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = (
            fake.CDOT_SNAPSHOT_BUSY_SNAPMIRROR)
        mock_is_flexgroup_share = self.mock_object(
            self.library, '_delete_busy_snapshot')

        self.assertRaises(exception.ShareSnapshotIsBusy,
                          self.library._delete_snapshot,
                          vserver_client,
                          fake.SHARE_NAME,
                          fake.SNAPSHOT_NAME)

        self.assertFalse(vserver_client.delete_snapshot.called)
        self.assertFalse(vserver_client.get_clone_children_for_snapshot.called)
        self.assertFalse(vserver_client.split_volume_clone.called)
        self.assertFalse(mock_is_flexgroup_share.called)
        self.assertFalse(vserver_client.soft_delete_snapshot.called)

    def test_delete_busy_snapshot(self):
        (self.library.configuration.
            netapp_delete_busy_flexgroup_snapshot_timeout) = 2
        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = fake.CDOT_SNAPSHOT

        self.library._delete_busy_snapshot(vserver_client,
                                           fake.SHARE_NAME,
                                           fake.SNAPSHOT_NAME)

        vserver_client.get_snapshot.assert_called_once_with(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)
        vserver_client.delete_snapshot.assert_called_once_with(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)

    def test_delete_busy_snapshot_raise_timeout(self):
        (self.library.configuration.
         netapp_delete_busy_flexgroup_snapshot_timeout) = 2
        vserver_client = mock.Mock()
        vserver_client.get_snapshot.return_value = (
            fake.CDOT_SNAPSHOT_BUSY_VOLUME_CLONE)

        self.assertRaises(
            exception.NetAppException, self.library._delete_busy_snapshot,
            vserver_client, fake.SHARE_NAME, fake.SNAPSHOT_NAME)

    @ddt.data(None, fake.VSERVER1)
    def test_manage_existing(self, fake_vserver):

        vserver_client = mock.Mock()
        mock__get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        mock_manage_container = self.mock_object(
            self.library,
            '_manage_container',
            mock.Mock(return_value=fake.SHARE_SIZE))
        mock_create_export = self.mock_object(
            self.library,
            '_create_export',
            mock.Mock(return_value=fake.NFS_EXPORTS))

        result = self.library.manage_existing(fake.SHARE, {},
                                              share_server=fake_vserver)

        expected = {
            'size': fake.SHARE_SIZE,
            'export_locations': fake.NFS_EXPORTS
        }

        mock__get_vserver.assert_called_once_with(share_server=fake_vserver)
        mock_manage_container.assert_called_once_with(fake.SHARE,
                                                      fake.VSERVER1,
                                                      vserver_client)

        mock_create_export.assert_called_once_with(fake.SHARE,
                                                   fake_vserver,
                                                   fake.VSERVER1,
                                                   vserver_client)
        self.assertDictEqual(expected, result)

    @ddt.data(None, fake.VSERVER1)
    def test_unmanage(self, fake_vserver):

        result = self.library.unmanage(fake.SHARE, share_server=fake_vserver)

        self.assertIsNone(result)

    @ddt.data({'qos': True, 'fpolicy': False, 'is_flexgroup': False},
              {'qos': False, 'fpolicy': True, 'is_flexgroup': False},
              {'qos': True, 'fpolicy': False, 'is_flexgroup': True},
              {'qos': False, 'fpolicy': True, 'is_flexgroup': True})
    @ddt.unpack
    def test_manage_container(self, qos, fpolicy, is_flexgroup):

        vserver_client = mock.Mock()
        self.library._have_cluster_creds = True
        qos_policy_group_name = fake.QOS_POLICY_GROUP_NAME if qos else None
        if qos:
            extra_specs = copy.deepcopy(fake.EXTRA_SPEC_WITH_QOS)
        elif fpolicy:
            extra_specs = copy.deepcopy(fake.EXTRA_SPEC_WITH_FPOLICY)
        else:
            extra_specs = copy.deepcopy(fake.EXTRA_SPEC)
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

        fake_aggr = [fake.POOL_NAME] if is_flexgroup else fake.POOL_NAME
        mock_is_flexgroup_pool = self.mock_object(
            self.library, '_is_flexgroup_pool',
            mock.Mock(return_value=is_flexgroup))
        mock_get_flexgroup_aggregate_list = self.mock_object(
            self.library, '_get_flexgroup_aggregate_list',
            mock.Mock(return_value=fake_aggr))
        mock_is_flexgroup_share = self.mock_object(
            self.library, '_is_flexgroup_share',
            mock.Mock(return_value=is_flexgroup))

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
        fake_fpolicy_scope = {
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'shares-to-include': [fake.FLEXVOL_NAME]
        }
        mock_find_scope = self.mock_object(
            self.library, '_find_reusable_fpolicy_scope',
            mock.Mock(return_value=fake_fpolicy_scope))
        mock_modify_fpolicy = self.mock_object(
            vserver_client, 'modify_fpolicy_scope')

        result = self.library._manage_container(share_to_manage,
                                                fake.VSERVER1,
                                                vserver_client)

        mock_is_flexgroup_pool.assert_called_once_with(fake.POOL_NAME)
        if is_flexgroup:
            mock_get_flexgroup_aggregate_list.assert_called_once_with(
                fake.POOL_NAME)
        else:
            mock_get_flexgroup_aggregate_list.assert_not_called()
        mock_is_flexgroup_share.assert_called_once_with(vserver_client,
                                                        fake.FLEXVOL_NAME)
        mock_get_volume_to_manage.assert_called_once_with(
            fake_aggr, fake.FLEXVOL_NAME)
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
            fake_aggr, fake.SHARE_NAME, **provisioning_opts)
        mock_modify_or_create_qos_policy.assert_called_once_with(
            share_to_manage, extra_specs, fake.VSERVER1, vserver_client)
        mock_validate_volume_for_manage.assert_called()
        if fpolicy:
            mock_find_scope.assert_called_once_with(
                share_to_manage, vserver_client,
                fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
                fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
                fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS,
                shares_to_include=[fake.FLEXVOL_NAME])
            mock_modify_fpolicy.assert_called_once_with(
                fake.SHARE_NAME,
                fake.FPOLICY_POLICY_NAME, shares_to_include=[fake.SHARE_NAME])
        else:
            mock_find_scope.assert_not_called()
            mock_modify_fpolicy.assert_not_called()

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

        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_share',
                         mock.Mock(return_value=False))

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

        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_share',
                         mock.Mock(return_value=False))

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

    def test_manage_container_invalid_fpolicy(self):
        vserver_client = mock.Mock()
        extra_spec = copy.deepcopy(fake.EXTRA_SPEC_WITH_FPOLICY)
        share_to_manage = copy.deepcopy(fake.SHARE)
        share_to_manage['export_location'] = fake.EXPORT_LOCATION

        mock_helper = mock.Mock()
        mock_helper.get_share_name_for_share.return_value = fake.FLEXVOL_NAME
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock_helper))

        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_share',
                         mock.Mock(return_value=False))

        self.mock_object(vserver_client,
                         'get_volume_to_manage',
                         mock.Mock(return_value=fake.FLEXVOL_TO_MANAGE))
        self.mock_object(self.library, '_validate_volume_for_manage')
        self.mock_object(share_types,
                         'get_extra_specs_from_share',
                         mock.Mock(return_value=extra_spec))
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_find_reusable_fpolicy_scope',
                         mock.Mock(return_value=None))

        self.assertRaises(exception.ManageExistingShareTypeMismatch,
                          self.library._manage_container,
                          share_to_manage,
                          fake.VSERVER1,
                          vserver_client)

    def test_manage_container_wrong_pool_style(self):

        vserver_client = mock.Mock()

        share_to_manage = copy.deepcopy(fake.SHARE)
        share_to_manage['export_location'] = fake.EXPORT_LOCATION

        mock_helper = mock.Mock()
        mock_helper.get_share_name_for_share.return_value = fake.FLEXVOL_NAME
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock_helper))

        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_share',
                         mock.Mock(return_value=True))

        self.assertRaises(exception.ManageInvalidShare,
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

    @ddt.data(
        {'fake_vserver': None, 'is_flexgroup': False},
        {'fake_vserver': fake.VSERVER1, 'is_flexgroup': False},
        {'fake_vserver': None, 'is_flexgroup': True},
        {'fake_vserver': fake.VSERVER1, 'is_flexgroup': True})
    @ddt.unpack
    def test_manage_existing_snapshot(self, fake_vserver, is_flexgroup):

        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        vserver_client.get_volume.return_value = fake.FLEXVOL_TO_MANAGE
        vserver_client.snapshot_exists.return_value = True
        vserver_client.volume_has_snapmirror_relationships.return_value = False

        result = self.library.manage_existing_snapshot(
            fake.SNAPSHOT_TO_MANAGE, {}, share_server=fake_vserver)

        share_name = self.library._get_backend_share_name(
            fake.SNAPSHOT['share_id'])
        mock_get_vserver.assert_called_once_with(share_server=fake_vserver)
        vserver_client.snapshot_exists.assert_called_once_with(
            fake.SNAPSHOT_NAME, share_name)
        (vserver_client.volume_has_snapmirror_relationships.
            assert_called_once_with(fake.FLEXVOL_TO_MANAGE))
        expected_result = {'size': 2}
        self.assertEqual(expected_result, result)

    def test_manage_existing_snapshot_no_snapshot_name(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        vserver_client.get_volume.return_value = fake.FLEXVOL_TO_MANAGE
        vserver_client.snapshot_exists.return_value = True
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

    def test_manage_existing_snapshot_not_from_share(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        vserver_client.get_volume.return_value = fake.FLEXVOL_TO_MANAGE
        vserver_client.snapshot_exists.return_value = False

        self.assertRaises(exception.ManageInvalidShareSnapshot,
                          self.library.manage_existing_snapshot,
                          fake.SNAPSHOT_TO_MANAGE, {})

    def test_manage_existing_snapshot_mirrors_present(self):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        vserver_client.get_volume.return_value = fake.FLEXVOL_TO_MANAGE
        vserver_client.snapshot_exists.return_value = True
        vserver_client.volume_has_snapmirror_relationships.return_value = True

        self.assertRaises(exception.ManageInvalidShareSnapshot,
                          self.library.manage_existing_snapshot,
                          fake.SNAPSHOT_TO_MANAGE, {})

    @ddt.data(None, fake.VSERVER1)
    def test_unmanage_snapshot(self, fake_vserver):

        result = self.library.unmanage_snapshot(fake.SNAPSHOT, fake_vserver)

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

    def test_shrinking_possible_data_loss(self):

        naapi_error = self._mock_api_error(code=netapp_api.EVOLOPNOTSUPP,
                                           message='Possible data loss')

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))

        mock_set_volume_size = self.mock_object(
            vserver_client, 'set_volume_size', naapi_error)

        new_size = fake.SHARE['size'] - 1

        self.assertRaises(exception.ShareShrinkingPossibleDataLoss,
                          self.library.shrink_share,
                          fake.SHARE, new_size)

        self.library._get_vserver.assert_called_once_with(share_server=None)
        mock_set_volume_size.assert_called_once_with(fake.SHARE_NAME, new_size)

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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=True))
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=True))
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=True))
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
        fake_share_copy = copy.deepcopy(fake.SHARE)
        fake_share_copy['replica_state'] = constants.REPLICA_STATE_ACTIVE
        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=True))
        protocol_helper = mock.Mock()
        protocol_helper.update_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        mock_share_exists = self.mock_object(self.library,
                                             '_share_exists',
                                             mock.Mock(return_value=True))

        self.library.update_access(self.context,
                                   fake_share_copy,
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

    @ddt.data(True, False)
    def test_update_access_to_in_sync_replica(self, is_readable):

        fake_share_copy = copy.deepcopy(fake.SHARE)
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=is_readable))
        fake_share_copy['replica_state'] = constants.REPLICA_STATE_IN_SYNC
        vserver_client = mock.Mock()
        mock_get_vserver = self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(return_value=(fake.VSERVER1, vserver_client)))
        protocol_helper = mock.Mock()
        protocol_helper.update_access.return_value = None
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        self.mock_object(self.library, '_share_exists',
                         mock.Mock(return_value=True))

        self.library.update_access(self.context,
                                   fake_share_copy,
                                   [fake.SHARE_ACCESS],
                                   [],
                                   [],
                                   share_server=fake.SHARE_SERVER)

        if is_readable:
            mock_get_vserver.assert_called_once_with(
                share_server=fake.SHARE_SERVER)
        else:
            mock_get_vserver.assert_not_called()

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

        self.library._flexgroup_pools = fake.FLEXGROUP_POOL_OPT
        self.library._have_cluster_creds = True
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library,
                         '_get_flexgroup_aggr_set',
                         mock.Mock(return_value=fake.FLEXGROUP_AGGR_SET))
        self.mock_object(self.library,
                         '_get_aggregate_info',
                         mock.Mock(return_value=fake.SSC_INFO_MAP))

        self.library._update_ssc_info()

        expected = {
            fake.AGGREGATES[0]: {
                'netapp_aggregate': fake.AGGREGATES[0],
                'netapp_flexgroup': False,
                'netapp_raid_type': 'raid4',
                'netapp_disk_type': ['FCAL'],
                'netapp_hybrid_aggregate': 'false',
            },
            fake.AGGREGATES[1]: {
                'netapp_aggregate': fake.AGGREGATES[1],
                'netapp_flexgroup': False,
                'netapp_raid_type': 'raid_dp',
                'netapp_disk_type': ['SATA', 'SSD'],
                'netapp_hybrid_aggregate': 'true',
            },
            fake.FLEXGROUP_POOL_NAME: {
                'netapp_aggregate': fake.FLEXGROUP_POOL['netapp_aggregate'],
                'netapp_flexgroup': True,
                'netapp_raid_type': 'raid4 raid_dp',
                'netapp_disk_type': ['FCAL', 'SATA', 'SSD'],
                'netapp_hybrid_aggregate': 'false true',
            },
        }

        self.assertEqual(expected, self.library._ssc_stats)

    def test_update_ssc_info_no_aggregates(self):

        self.library._flexgroup_pools = {}
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=[]))

        self.library._update_ssc_info()

        self.assertDictEqual({}, self.library._ssc_stats)

    def test_update_ssc_info_no_cluster_creds(self):

        self.library._flexgroup_pools = fake.FLEXGROUP_POOL_OPT
        self.library._have_cluster_creds = False
        self.mock_object(self.library,
                         '_find_matching_aggregates',
                         mock.Mock(return_value=fake.AGGREGATES))
        self.mock_object(self.library,
                         '_get_flexgroup_aggr_set',
                         mock.Mock(return_value=fake.FLEXGROUP_AGGR_SET))
        self.mock_object(self.library,
                         '_get_aggregate_info',
                         mock.Mock(return_value=fake.SSC_INFO_MAP))

        self.library._update_ssc_info()

        expected = {
            fake.AGGREGATES[0]: {
                'netapp_aggregate': fake.AGGREGATES[0],
                'netapp_flexgroup': False,
            },
            fake.AGGREGATES[1]: {
                'netapp_aggregate': fake.AGGREGATES[1],
                'netapp_flexgroup': False,
            },
            fake.FLEXGROUP_POOL_NAME: {
                'netapp_aggregate': fake.FLEXGROUP_POOL['netapp_aggregate'],
                'netapp_flexgroup': True,
            },
        }

        self.assertDictEqual(self.library._ssc_stats, expected)

    def test_get_aggregate_info(self):
        mock_get_aggregate = self.mock_object(
            self.client, 'get_aggregate',
            mock.Mock(side_effect=fake.SSC_AGGREGATES))
        mock_get_aggregate_disk_types = self.mock_object(
            self.client, 'get_aggregate_disk_types',
            mock.Mock(side_effect=fake.SSC_DISK_TYPES))

        result = self.library._get_aggregate_info(fake.AGGREGATES)

        expected = {
            fake.AGGREGATES[0]: {
                'netapp_raid_type': 'raid4',
                'netapp_disk_type': 'FCAL',
                'netapp_hybrid_aggregate': 'false',
            },
            fake.AGGREGATES[1]: {
                'netapp_raid_type': 'raid_dp',
                'netapp_disk_type': ['SATA', 'SSD'],
                'netapp_hybrid_aggregate': 'true',
            },
        }

        self.assertDictEqual(result, expected)
        mock_get_aggregate.assert_has_calls([
            mock.call(fake.AGGREGATES[0]),
            mock.call(fake.AGGREGATES[1]),
        ])
        mock_get_aggregate_disk_types.assert_has_calls([
            mock.call(fake.AGGREGATES[0]),
            mock.call(fake.AGGREGATES[1]),
        ])

    @ddt.data(
        {'is_readable': True, 'rules_status': constants.STATUS_ACTIVE},
        {'is_readable': True, 'rules_status': (
            constants.SHARE_INSTANCE_RULES_ERROR)},
        {'is_readable': False, 'rules_status': constants.STATUS_ACTIVE})
    @ddt.unpack
    def test_create_replica(self, is_readable, rules_status):

        vserver_client = mock.Mock()
        self.mock_object(self.library,
                         '_allocate_container')
        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=vserver_client))
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        mock_is_readable = self.mock_object(
            self.library, '_is_readable_replica',
            mock.Mock(return_value=is_readable))

        mock_create_export = self.mock_object(
            self.library, '_create_export', mock.Mock(return_value=[]))
        protocol_helper = mock.Mock()
        if rules_status == constants.STATUS_ACTIVE:
            protocol_helper.update_access.return_value = None
        else:
            protocol_helper.update_access.side_effect = (
                netapp_api.NaApiError(code=0))
        mock_get_helper = self.mock_object(
            self.library, '_get_helper',
            mock.Mock(return_value=protocol_helper))
        self.mock_object(mock_dm_session, 'get_backend_info_for_share',
                         mock.Mock(return_value=(fake.SHARE_NAME,
                                                 fake.VSERVER1,
                                                 fake.BACKEND_NAME)))
        self.mock_object(self.library, '_is_flexgroup_share',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(na_utils, 'get_relationship_type',
                         mock.Mock(return_value=na_utils.DATA_PROTECTION_TYPE))
        expected_model_update = {
            'export_locations': [],
            'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC,
            'access_rules_status': rules_status,
        }

        model_update = self.library.create_replica(
            None, [fake.SHARE], fake.SHARE, [fake.SHARE_ACCESS], [],
            share_server=None)

        self.assertDictEqual(expected_model_update, model_update)
        mock_dm_session.create_snapmirror.assert_called_once_with(
            fake.SHARE, fake.SHARE, na_utils.DATA_PROTECTION_TYPE,
            mount=is_readable)
        mock_is_readable.assert_called_once_with(fake.SHARE)
        if is_readable:
            mock_create_export.assert_called_once_with(
                fake.SHARE, None, fake.VSERVER1, vserver_client, replica=True)
            mock_get_helper.assert_called_once_with(fake.SHARE)
            protocol_helper.update_access.assert_called_once_with(
                fake.SHARE, fake.SHARE_NAME, [fake.SHARE_ACCESS])
        else:
            mock_create_export.assert_not_called()
            mock_get_helper.assert_not_called()
            protocol_helper.update_access.assert_not_called()

        data_motion.get_client_for_backend.assert_has_calls(
            [mock.call(fake.BACKEND_NAME, vserver_name=fake.VSERVER1),
             mock.call(fake.BACKEND_NAME, vserver_name=fake.VSERVER1)])
        self.library._is_flexgroup_pool.assert_called_once_with(fake.POOL_NAME)
        na_utils.get_relationship_type.assert_called_once_with(False)

    def test_create_replica_with_share_server(self):
        self.mock_object(self.library,
                         '_allocate_container',
                         mock.Mock())
        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(mock_dm_session, 'get_backend_info_for_share',
                         mock.Mock(return_value=(fake.SHARE_NAME,
                                                 fake.VSERVER1,
                                                 fake.BACKEND_NAME)))
        self.mock_object(self.library, '_is_flexgroup_share',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(data_motion, 'get_client_for_backend')
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        expected_model_update = {
            'export_locations': [],
            'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC,
            'access_rules_status': constants.STATUS_ACTIVE,
        }

        model_update = self.library.create_replica(
            None, [fake.SHARE], fake.SHARE, [], [],
            share_server=fake.SHARE_SERVER)

        self.assertDictEqual(expected_model_update, model_update)
        mock_dm_session.create_snapmirror.assert_called_once_with(
            fake.SHARE, fake.SHARE, na_utils.DATA_PROTECTION_TYPE,
            mount=False)
        data_motion.get_client_for_backend.assert_has_calls(
            [mock.call(fake.BACKEND_NAME, vserver_name=fake.VSERVER1),
             mock.call(fake.BACKEND_NAME, vserver_name=fake.VSERVER1)])
        self.library._is_flexgroup_pool.assert_called_once_with(fake.POOL_NAME)

    def test_create_replica_raise_different_type(self):

        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(mock_dm_session, 'get_backend_info_for_share',
                         mock.Mock(return_value=(fake.SHARE_NAME,
                                                 fake.VSERVER1,
                                                 fake.BACKEND_NAME)))
        self.mock_object(self.library, '_is_flexgroup_share',
                         mock.Mock(return_value=True))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(data_motion, 'get_client_for_backend')

        self.assertRaises(exception.NetAppException,
                          self.library.create_replica,
                          None, [fake.SHARE], fake.SHARE, [], [],
                          share_server=None)

    def test_create_replica_raise_flexgroup_no_fan_out_limit(self):

        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(mock_dm_session, 'get_backend_info_for_share',
                         mock.Mock(return_value=(fake.SHARE_NAME,
                                                 fake.VSERVER1,
                                                 fake.BACKEND_NAME)))
        self.mock_object(self.library, '_is_flexgroup_share',
                         mock.Mock(return_value=True))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=True))

        mock_src_client = mock.Mock()
        self.mock_object(mock_src_client,
                         'is_flexgroup_fan_out_supported',
                         mock.Mock(return_value=False))
        self.mock_object(self.library._client,
                         'is_flexgroup_fan_out_supported',
                         mock.Mock(return_value=False))
        self.mock_object(data_motion, 'get_client_for_backend',
                         mock.Mock(return_value=mock_src_client))

        self.assertRaises(exception.NetAppException,
                          self.library.create_replica,
                          None, [fake.SHARE, fake.SHARE, fake.SHARE],
                          fake.SHARE, [], [], share_server=None)

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
                         '_delete_share',
                         mock.Mock())
        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(data_motion, 'get_client_for_backend')
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))

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
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_delete_share',
                         mock.Mock())
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

    @ddt.data({'seconds': 3600, 'schedule': 'hourly'},
              {'seconds': (5 * 3600), 'schedule': '5hourly'},
              {'seconds': (30 * 60), 'schedule': '30minute'},
              {'seconds': (2 * 24 * 3600), 'schedule': '2DAY'},
              {'seconds': 3600, 'schedule': 'fake_shedule'},
              {'seconds': 3600, 'schedule': 'fake2'},
              {'seconds': 3600, 'schedule': '10fake'})
    @ddt.unpack
    def test__convert_schedule_to_seconds(self, seconds, schedule):
        expected_return = seconds
        actual_return = self.library._convert_schedule_to_seconds(schedule)
        self.assertEqual(expected_return, actual_return)

    def test_update_replica_state_no_snapmirror_share_creating(self):
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(return_value=[])
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        self.mock_object(share_utils,
                         'extract_host',
                         mock.Mock(return_value=fake.POOL_NAME))
        self.mock_object(self.library,
                         '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(na_utils,
                         'get_relationship_type',
                         mock.Mock(return_value=na_utils.DATA_PROTECTION_TYPE))
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        self.mock_object(share_utils,
                         'extract_host',
                         mock.Mock(return_value=fake.POOL_NAME))
        self.mock_object(self.library,
                         '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(na_utils,
                         'get_relationship_type',
                         mock.Mock(return_value=na_utils.DATA_PROTECTION_TYPE))

        replica = copy.deepcopy(fake.SHARE)
        replica['status'] = status

        result = self.library.update_replica_state(
            None, [replica], replica, None, [], share_server=None)

        self.assertEqual(1,
                         self.mock_dm_session.create_snapmirror.call_count)
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)

        vserver_client.resync_snapmirror_vol.assert_called_once_with(
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))

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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        vserver_client.resync_snapmirror_vol.side_effect = (
            netapp_api.NaApiError)

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)

        vserver_client.resync_snapmirror_vol.assert_called_once_with(
            fake.VSERVER2, 'fake_volume', fake.VSERVER1, fake.SHARE['name']
        )

        self.assertEqual(constants.STATUS_ERROR, result)

    def test_update_replica_state_stale_snapmirror(self):
        fake_snapmirror = {
            'mirror-state': 'snapmirrored',
            'schedule': self.library.configuration.netapp_snapmirror_schedule,
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        mock_backend_config = fake.get_config_cmode()
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)

        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC, result)

    def test_update_replica_state_in_sync(self):
        fake_snapmirror = {
            'mirror-state': 'snapmirrored',
            'schedule': self.library.configuration.netapp_snapmirror_schedule,
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        mock_backend_config = fake.get_config_cmode()
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, [],
                                                   share_server=None)

        (self.mock_dm_session.cleanup_previous_snapmirror_relationships
         .assert_not_called())
        self.assertEqual(constants.REPLICA_STATE_IN_SYNC, result)

    def test_update_replica_state_replica_change_to_in_sycn(self):
        fake_snapmirror = {
            'mirror-state': 'snapmirrored',
            'relationship-status': 'idle',
            'last-transfer-end-timestamp': '%s' % float(time.time())
        }
        # fake SHARE has replica_state set to active already
        active_replica = fake.SHARE
        out_of_sync_replica = copy.deepcopy(fake.SHARE)
        out_of_sync_replica['replica_state'] = (
            constants.REPLICA_STATE_OUT_OF_SYNC)
        replica_list = [out_of_sync_replica, active_replica]
        vserver_client = mock.Mock()
        self.mock_object(vserver_client, 'volume_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 vserver_client)))
        self.mock_dm_session.get_snapmirrors = mock.Mock(
            return_value=[fake_snapmirror])
        mock_config = mock.Mock()
        mock_config.safe_get = mock.Mock(return_value=0)
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_config))
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))

        result = self.library.update_replica_state(
            None, replica_list, out_of_sync_replica,
            None, [], share_server=None)

        # Expect a snapmirror cleanup as replica was in out of sync state
        (self.mock_dm_session.cleanup_previous_snapmirror_relationships
         .assert_called_once_with(out_of_sync_replica, replica_list))
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
            'schedule': self.library.configuration.netapp_snapmirror_schedule,
            'relationship-status': 'idle',
            'last-transfer-end-timestamp': '%s' % float(time.time())
        }
        fake_snapshot = copy.deepcopy(fake.SNAPSHOT)
        fake_snapshot['share_id'] = fake.SHARE['id']
        fake_snapshot['provider_location'] = 'fake'
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        mock_backend_config = fake.get_config_cmode()
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, snapshots,
                                                   share_server=None)

        (self.mock_dm_session.cleanup_previous_snapmirror_relationships
         .assert_not_called())
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
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        mock_backend_config = fake.get_config_cmode()
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        result = self.library.update_replica_state(None, [fake.SHARE],
                                                   fake.SHARE, None, snapshots,
                                                   share_server=None)

        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC, result)

    @ddt.data(True, False)
    def test_promote_replica(self, is_readable):
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        protocol_helper = mock.Mock()
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))
        self.mock_object(self.library, '_unmount_orig_active_replica')
        self.mock_object(self.library, '_handle_qos_on_replication_change')
        self.mock_object(self.library,
                         '_is_flexgroup_pool',
                         mock.Mock(return_value=False))

        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))
        self.mock_object(mock_dm_session, 'get_backend_info_for_share',
                         mock.Mock(return_value=(fake.SHARE_NAME,
                                                 fake.VSERVER1,
                                                 fake.BACKEND_NAME)))
        mock_client = mock.Mock()
        self.mock_object(data_motion, "get_client_for_backend",
                         mock.Mock(return_value=mock_client))
        mock_backend_config = fake.get_config_cmode()
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))
        self.mock_object(self.client, 'cleanup_demoted_replica')
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=is_readable))
        self.mock_object(self.library,
                         '_update_autosize_attributes_after_promote_replica')
        replicas = self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2],
            self.fake_replica_2, [], share_server=None)

        mock_dm_session.change_snapmirror_source.assert_called_once_with(
            self.fake_replica, self.fake_replica, self.fake_replica_2,
            mock.ANY, is_flexgroup=False
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
        if is_readable:
            self.library._unmount_orig_active_replica.assert_not_called()
            protocol_helper.cleanup_demoted_replica.assert_not_called()
            self.assertEqual('fake_export_location',
                             actual_replica_1['export_locations'])
        else:
            self.library._unmount_orig_active_replica.assert_called_once_with(
                self.fake_replica, fake.VSERVER1)
            protocol_helper.cleanup_demoted_replica.assert_called_once_with(
                self.fake_replica, fake.SHARE['name'])
            self.assertEqual([], actual_replica_1['export_locations'])
        self.library._handle_qos_on_replication_change.assert_called_once()

    def test_promote_replica_cleanup_demoted_storage_error(self):
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        protocol_helper = mock.Mock()
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))
        self.mock_object(self.library, '_unmount_orig_active_replica')
        self.mock_object(self.library, '_handle_qos_on_replication_change')
        self.mock_object(self.library,
                         '_is_flexgroup_pool',
                         mock.Mock(return_value=False))

        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))
        self.mock_object(
            protocol_helper, 'cleanup_demoted_replica',
            mock.Mock(side_effect=exception.StorageCommunicationException))
        self.mock_object(self.library,
                         '_update_autosize_attributes_after_promote_replica')
        mock_log = self.mock_object(lib_base.LOG, 'exception')

        self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2],
            self.fake_replica_2, [], share_server=None)

        mock_dm_session.change_snapmirror_source.assert_called_once_with(
            self.fake_replica, self.fake_replica, self.fake_replica_2,
            mock.ANY, is_flexgroup=False
        )
        protocol_helper.cleanup_demoted_replica.assert_called_once_with(
            self.fake_replica, fake.SHARE['name'])
        mock_log.assert_called_once()

    def test_promote_replica_destination_unreachable(self):
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock.Mock()))
        self.mock_object(self.library, '_unmount_orig_active_replica')
        self.mock_object(self.library, '_handle_qos_on_replication_change')

        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))
        self.mock_object(
            self.library, '_convert_destination_replica_to_independent',
            mock.Mock(side_effect=exception.StorageCommunicationException))
        self.mock_object(self.library,
                         '_update_autosize_attributes_after_promote_replica')

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
            self.library._unmount_orig_active_replica.called)
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
        self.mock_object(self.library, '_unmount_orig_active_replica')
        self.mock_object(self.library, '_handle_qos_on_replication_change')
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock.Mock()))

        self.mock_object(self.library,
                         '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))
        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_update_autosize_attributes_after_promote_replica')

        replicas = self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2, fake_replica_3],
            self.fake_replica_2, [], share_server=None)

        mock_dm_session.change_snapmirror_source.assert_has_calls([
            mock.call(fake_replica_3, self.fake_replica, self.fake_replica_2,
                      mock.ANY, is_flexgroup=False),
            mock.call(self.fake_replica, self.fake_replica,
                      self.fake_replica_2, mock.ANY, is_flexgroup=False)
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
        self.library._unmount_orig_active_replica.assert_called_once_with(
            self.fake_replica, fake.VSERVER1)
        self.library._handle_qos_on_replication_change.assert_called_once()

    def test_promote_replica_with_access_rules(self):
        self.mock_object(self.library,
                         '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1,
                                                 mock.Mock())))
        self.mock_object(self.library, '_unmount_orig_active_replica')
        self.mock_object(self.library, '_handle_qos_on_replication_change')
        mock_helper = mock.Mock()
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=mock_helper))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))
        self.mock_object(self.library,
                         '_is_flexgroup_pool',
                         mock.Mock(return_value=False))

        mock_dm_session = mock.Mock()
        self.mock_object(data_motion, "DataMotionSession",
                         mock.Mock(return_value=mock_dm_session))
        self.mock_object(mock_dm_session, 'get_vserver_from_share',
                         mock.Mock(return_value=fake.VSERVER1))
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_update_autosize_attributes_after_promote_replica')

        replicas = self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2],
            self.fake_replica_2, [fake.SHARE_ACCESS], share_server=None)

        mock_dm_session.change_snapmirror_source.assert_has_calls([
            mock.call(self.fake_replica, self.fake_replica,
                      self.fake_replica_2, mock.ANY, is_flexgroup=False)
        ], any_order=True)
        self.assertEqual(2, len(replicas))
        share_name = self.library._get_backend_share_name(
            self.fake_replica_2['id'])
        mock_helper.update_access.assert_called_once_with(self.fake_replica_2,
                                                          share_name,
                                                          [fake.SHARE_ACCESS])
        self.library._unmount_orig_active_replica.assert_called_once_with(
            self.fake_replica, fake.VSERVER1)
        self.library._handle_qos_on_replication_change.assert_called_once()

    def test_unmount_orig_active_replica(self):
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value=fake.MANILA_HOST_NAME))
        self.mock_object(data_motion, 'get_client_for_backend')
        self.mock_object(self.library, '_get_backend_share_name', mock.Mock(
            return_value=fake.SHARE_NAME))

        result = self.library._unmount_orig_active_replica(fake.SHARE)
        self.assertIsNone(result)

    @ddt.data({'extra_specs': {'netapp:snapshot_policy': 'none'},
               'have_cluster_creds': True},
              {'extra_specs': {'netapp:snapshot_policy': 'none'},
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
            True, share_server=fake.SHARE_SERVER)

        self.assertIsNone(retval)
        lib_base.LOG.exception.assert_not_called()
        lib_base.LOG.info.assert_not_called()
        if have_cluster_creds:
            share_types.get_extra_specs_from_share.assert_called_once_with(
                self.fake_replica)
        else:
            share_types.get_extra_specs_from_share.assert_not_called()

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
            self.mock_dm_session, self.fake_replica_2, self.fake_replica, True,
            share_server=fake.SHARE_SERVER)

        self.assertIsNone(retval)
        (self.mock_dm_session.remove_qos_on_old_active_replica
         .assert_called_once_with(self.fake_replica))
        lib_base.LOG.exception.assert_called_once()
        lib_base.LOG.info.assert_not_called()
        vserver_client.set_qos_policy_group_for_volume.assert_not_called()

    @ddt.data(True, False)
    def test_handle_qos_on_replication_change_modify_existing_policy(self,
                                                                     is_dr):
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
            is_dr, share_server=fake.SHARE_SERVER)

        self.assertIsNone(retval)
        if is_dr:
            (self.mock_dm_session.remove_qos_on_old_active_replica.
                assert_called_once_with(self.fake_replica))
        else:
            (self.mock_dm_session.remove_qos_on_old_active_replica.
                assert_not_called())
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
            self.mock_dm_session, self.fake_replica_2, self.fake_replica, True,
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
            self.fake_replica, self.fake_replica_2,
            quiesce_wait_time=None)

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
            self.fake_replica, self.fake_replica_2,
            quiesce_wait_time=None)

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
        self.mock_object(self.library,
                         '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_is_readable_replica',
                         mock.Mock(return_value=False))
        self.mock_object(self.library,
                         '_update_autosize_attributes_after_promote_replica')
        replicas = self.library.promote_replica(
            None, [self.fake_replica, self.fake_replica_2],
            self.fake_replica_2, fake_access_rules, share_server=None)

        self.mock_dm_session.change_snapmirror_source.assert_called_once_with(
            self.fake_replica, self.fake_replica, self.fake_replica_2,
            mock.ANY, is_flexgroup=False
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
            self.fake_replica, self.fake_replica_2,
            quiesce_wait_time=None)

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
            self.fake_replica, self.fake_replica_2,
            quiesce_wait_time=None)

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

    @ddt.data(True, False)
    def test_safe_change_replica_source(self, is_dr):
        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        fake_replica_3['replica_state'] = constants.REPLICA_STATE_OUT_OF_SYNC
        protocol_helper = mock.Mock()
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        self.mock_object(self.library, '_create_export',
                         mock.Mock(return_value='fake_export_location'))
        self.mock_object(self.library, '_unmount_orig_active_replica')
        self.mock_object(self.library, '_handle_qos_on_replication_change')

        mock_dm_session = mock.Mock()
        mock_dm_session.wait_for_mount_replica.return_value = None
        self.mock_object(mock_dm_session, 'get_backend_info_for_share',
                         mock.Mock(return_value=(fake.SHARE_NAME,
                                                 fake.VSERVER1,
                                                 fake.BACKEND_NAME)))
        mock_client = mock.Mock()
        self.mock_object(data_motion, "get_client_for_backend",
                         mock.Mock(return_value=mock_client))
        mock_backend_config = fake.get_config_cmode()
        mock_backend_config.netapp_mount_replica_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        replica = self.library._safe_change_replica_source(
            mock_dm_session, self.fake_replica, self.fake_replica_2,
            fake_replica_3, [self.fake_replica, self.fake_replica_2,
                             fake_replica_3], is_dr, [fake.SHARE_ACCESS]
        )

        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC,
                         replica['replica_state'])
        if is_dr:
            self.assertEqual([], replica['export_locations'])
            mock_dm_session.wait_for_mount_replica.assert_not_called()
        else:
            self.assertEqual('fake_export_location',
                             replica['export_locations'])
            mock_dm_session.wait_for_mount_replica.assert_called_once_with(
                mock_client, fake.SHARE_NAME, timeout=30)

    @ddt.data({'fail_create_export': False, 'fail_mount': True},
              {'fail_create_export': True, 'fail_mount': False})
    @ddt.unpack
    def test_safe_change_replica_source_fail_recover_readable(
            self, fail_create_export, fail_mount):

        fake_replica_3 = copy.deepcopy(self.fake_replica_2)
        fake_replica_3['id'] = fake.SHARE_ID3
        fake_replica_3['replica_state'] = constants.REPLICA_STATE_OUT_OF_SYNC
        protocol_helper = mock.Mock()
        self.mock_object(self.library,
                         '_get_helper',
                         mock.Mock(return_value=protocol_helper))
        if fail_create_export:
            self.mock_object(self.library, '_create_export',
                             mock.Mock(side_effect=netapp_api.NaApiError()))
        else:
            self.mock_object(self.library, '_create_export',
                             mock.Mock(return_value='fake_export_location'))
        self.mock_object(self.library, '_unmount_orig_active_replica')
        self.mock_object(self.library, '_handle_qos_on_replication_change')
        mock_dm_session = mock.Mock()
        if fail_mount:
            mock_dm_session.wait_for_mount_replica.side_effect = (
                netapp_api.NaApiError())
        else:
            mock_dm_session.wait_for_mount_replica.return_value = None
        self.mock_object(mock_dm_session, 'get_backend_info_for_share',
                         mock.Mock(return_value=(fake.SHARE_NAME,
                                                 fake.VSERVER1,
                                                 fake.BACKEND_NAME)))
        mock_client = mock.Mock()
        self.mock_object(data_motion, "get_client_for_backend",
                         mock.Mock(return_value=mock_client))
        mock_backend_config = fake.get_config_cmode()
        mock_backend_config.netapp_mount_replica_timeout = 30
        self.mock_object(data_motion, 'get_backend_configuration',
                         mock.Mock(return_value=mock_backend_config))

        replica = self.library._safe_change_replica_source(
            mock_dm_session, self.fake_replica, self.fake_replica_2,
            fake_replica_3, [self.fake_replica, self.fake_replica_2,
                             fake_replica_3], False, [fake.SHARE_ACCESS]
        )

        self.assertEqual(constants.STATUS_ERROR,
                         replica['replica_state'])
        self.assertEqual(constants.STATUS_ERROR,
                         replica['status'])

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
                             fake_replica_3], True, [],
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
                             fake_replica_3], True, []
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

    @ddt.data(
        netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND),
        netapp_api.NaApiError(message='not initialized'))
    def test_create_replicated_snapshot_no_snapmirror(self, api_exception):
        self.mock_dm_session.update_snapmirror.side_effect = [
            None,
            api_exception
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

    @ddt.data(
        netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND),
        netapp_api.NaApiError(message='not initialized'))
    def test_delete_replicated_snapshot_missing_snapmirror(self,
                                                           api_exception):
        self.mock_dm_session.update_snapmirror.side_effect = [
            None,
            api_exception
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

    @ddt.data(
        netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND),
        netapp_api.NaApiError(message='not initialized'))
    def test_update_replicated_snapshot_no_snapmirror(self, api_exception):
        vserver_client = mock.Mock()
        vserver_client.snapshot_exists.return_value = False
        self.mock_dm_session.update_snapmirror.side_effect = api_exception
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

    @ddt.data(
        {'replication_type': constants.REPLICATION_TYPE_READABLE,
         'is_readable': True},
        {'replication_type': constants.REPLICATION_TYPE_DR,
         'is_readable': False},
        {'replication_type': constants.REPLICATION_TYPE_WRITABLE,
         'is_readable': False},
        {'replication_type': None,
         'is_readable': False})
    @ddt.unpack
    def test__is_readable_replica(self, replication_type, is_readable):
        extra_specs = {}
        if replication_type:
            extra_specs['replication_type'] = replication_type
        mock_get_extra_spec = self.mock_object(
            share_types, 'get_extra_specs_from_share',
            mock.Mock(return_value=extra_specs))

        result = self.library._is_readable_replica(fake.SHARE)

        self.assertEqual(is_readable, result)
        mock_get_extra_spec.assert_called_once_with(fake.SHARE)

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
        self.assertDictEqual(expected_compatibility, migration_compatibility)
        mock_warning_log.assert_called_once()
        self.assertFalse(data_motion.get_backend_configuration.called)

    @ddt.data(
        {'src_flexgroup': True, 'dest_flexgroup': False},
        {'src_flexgroup': False, 'dest_flexgroup': True})
    @ddt.unpack
    def test_migration_check_compatibility_flexgroup(self, src_flexgroup,
                                                     dest_flexgroup):
        self.library._have_cluster_creds = True
        mock_dm = mock.Mock()
        self.mock_object(data_motion, 'DataMotionSession',
                         mock.Mock(return_value=mock_dm))
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=dest_flexgroup))
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(share_utils, 'extract_host',
                         mock.Mock(return_value=fake.POOL_NAME))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=src_flexgroup))

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
        self.assertDictEqual(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        self.library._is_flexgroup_pool.assert_called_once_with(fake.POOL_NAME)
        if src_flexgroup:
            self.library.is_flexgroup_destination_host.assert_not_called()

    @ddt.data((None, exception.NetAppException),
              (exception.Invalid, None))
    @ddt.unpack
    def test_migration_check_compatibility_extra_specs_invalid(
            self, side_effect_1, side_effect_2):
        self.library._have_cluster_creds = True
        mock_dm = mock.Mock()
        self.mock_object(data_motion, 'DataMotionSession',
                         mock.Mock(return_value=mock_dm))
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=[
                'destination_backend', 'destination_pool', 'source_pool']))
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
        self.assertDictEqual(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        self.assertFalse(data_motion.get_backend_configuration.called)

    def test_migration_check_compatibility_invalid_qos_configuration(self):
        self.library._have_cluster_creds = True
        mock_dm = mock.Mock()
        self.mock_object(data_motion, 'DataMotionSession',
                         mock.Mock(return_value=mock_dm))
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=[
                'destination_backend', 'destination_pool', 'source_pool']))
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(
            self.library, '_get_provisioning_options',
            mock.Mock(return_value=fake.PROVISIONING_OPTS_WITH_ADAPT_QOS))
        self.mock_object(self.library, '_get_normalized_qos_specs',
                         mock.Mock(return_value=fake.QOS_NORMALIZED_SPEC))

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
        self.assertDictEqual(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()

    def test_migration_check_compatibility_destination_not_configured(self):
        self.library._have_cluster_creds = True
        mock_dm = mock.Mock()
        mock_dm = mock.Mock()
        self.mock_object(data_motion, 'DataMotionSession',
                         mock.Mock(return_value=mock_dm))
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(
            data_motion, 'get_backend_configuration',
            mock.Mock(side_effect=exception.BadConfigurationException(
                reason='fake_reason')))
        self.mock_object(self.library, '_get_vserver')
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            return_value='destination_backend'))
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_provisioning_options',
                         mock.Mock(return_value={}))
        self.mock_object(self.library, '_get_normalized_qos_specs')
        self.mock_object(self.library,
                         'validate_provisioning_options_for_share')
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
        self.assertDictEqual(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        self.assertFalse(mock_vserver_compatibility_check.called)
        self.assertFalse(self.library._get_vserver.called)

    @ddt.data(
        utils.annotated(
            'dest_share_server_not_expected',
            (('src_vserver', None), exception.InvalidParameterValue(
                err='fake_err'))),
        utils.annotated(
            'src_share_server_not_expected',
            (exception.InvalidParameterValue(err='fake_err'),
                ('dest_vserver', None))))
    def test_migration_check_compatibility_errors(self, side_effects):
        self.library._have_cluster_creds = True
        mock_dm = mock.Mock()
        self.mock_object(data_motion, 'DataMotionSession',
                         mock.Mock(return_value=mock_dm))
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(self.library, '_get_provisioning_options',
                         mock.Mock(return_value={}))
        self.mock_object(self.library, '_get_normalized_qos_specs')
        self.mock_object(self.library,
                         'validate_provisioning_options_for_share')
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
        self.assertDictEqual(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        self.assertFalse(mock_compatibility_check.called)

    def test_migration_check_compatibility_incompatible_vservers(self):
        self.library._have_cluster_creds = True
        mock_dm = mock.Mock()
        self.mock_object(data_motion, 'DataMotionSession',
                         mock.Mock(return_value=mock_dm))
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(data_motion, 'get_backend_configuration')
        self.mock_object(self.library, '_get_provisioning_options',
                         mock.Mock(return_value={}))
        self.mock_object(self.library, '_get_normalized_qos_specs')
        self.mock_object(self.library,
                         'validate_provisioning_options_for_share')
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        get_vserver_returns = [
            (fake.VSERVER1, mock.Mock()),
            (fake.VSERVER2, mock.Mock()),
        ]
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=get_vserver_returns))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=[
                'destination_backend', 'destination_pool', 'source_pool']))
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
        self.assertDictEqual(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        self.assertFalse(mock_move_check.called)
        self.library._get_vserver.assert_has_calls(
            [mock.call(share_server=fake.SHARE_SERVER),
             mock.call(share_server='dst_srv')])

    def test_migration_check_compatibility_client_error(self):
        self.library._have_cluster_creds = True
        mock_dm = mock.Mock()
        self.mock_object(data_motion, 'DataMotionSession',
                         mock.Mock(return_value=mock_dm))
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_provisioning_options',
                         mock.Mock(return_value={}))
        self.mock_object(self.library, '_get_normalized_qos_specs')
        self.mock_object(self.library,
                         'validate_provisioning_options_for_share')
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        self.mock_object(data_motion, 'get_backend_configuration')
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=[
                'destination_backend', 'destination_pool', 'source_pool']))
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
        self.assertDictEqual(expected_compatibility, migration_compatibility)
        mock_exception_log.assert_called_once()
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        mock_move_check.assert_called_once_with(
            fake.SHARE_NAME, fake.VSERVER1, 'destination_pool',
            encrypt_destination=False)
        self.library._get_vserver.assert_has_calls(
            [mock.call(share_server=fake.SHARE_SERVER),
             mock.call(share_server='dst_srv')])

    @ddt.data(False, True)
    def test_migration_check_compatibility(self, fpolicy):
        self.library._have_cluster_creds = True
        mock_dm = mock.Mock()
        self.mock_object(data_motion, 'DataMotionSession',
                         mock.Mock(return_value=mock_dm))
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        mock_dest_client = mock.Mock()
        if fpolicy:
            provisioning_options = copy.deepcopy(
                fake.PROVISIONING_OPTIONS_WITH_FPOLICY)
            get_vserver_side_effect = [(mock.Mock(), mock_dest_client),
                                       (fake.VSERVER1, mock.Mock())]
        else:
            get_vserver_side_effect = [(fake.VSERVER1, mock.Mock())]
            provisioning_options = {}
        self.mock_object(share_types, 'get_extra_specs_from_share')
        self.mock_object(self.library, '_check_extra_specs_validity')
        self.mock_object(self.library, '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(data_motion, 'get_backend_configuration')
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(side_effect=get_vserver_side_effect))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=[
                'destination_backend', 'destination_pool', 'source_pool']))
        mock_move_check = self.mock_object(self.client, 'check_volume_move')
        self.mock_object(self.library, '_get_dest_flexvol_encryption_value',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_get_provisioning_options',
                         mock.Mock(return_value=provisioning_options))
        self.mock_object(self.library, '_get_normalized_qos_specs')
        self.mock_object(self.library,
                         'validate_provisioning_options_for_share')
        self.mock_object(self.library,
                         '_check_destination_vserver_for_vol_move')
        fpolicies = [
            x for x in range(1, self.library.FPOLICY_MAX_VSERVER_POLICIES + 1)]
        mock_fpolicy_status = self.mock_object(
            mock_dest_client, 'get_fpolicy_policies_status',
            mock.Mock(return_value=fpolicies))
        mock_reusable_fpolicy = self.mock_object(
            self.library, '_find_reusable_fpolicy_scope',
            mock.Mock(return_value={'fake'}))

        src_instance = fake_share.fake_share_instance()
        dst_instance = fake_share.fake_share_instance()
        migration_compatibility = self.library.migration_check_compatibility(
            self.context, src_instance, dst_instance,
            share_server=fake.SHARE_SERVER, destination_share_server='dst_srv')

        expected_compatibility = {
            'compatible': True,
            'writable': True,
            'nondisruptive': True,
            'preserve_metadata': True,
            'preserve_snapshots': True,
        }
        self.assertDictEqual(expected_compatibility, migration_compatibility)
        data_motion.get_backend_configuration.assert_called_once_with(
            'destination_backend')
        mock_move_check.assert_called_once_with(
            fake.SHARE_NAME, fake.VSERVER1, 'destination_pool',
            encrypt_destination=False)
        if fpolicy:
            self.library._get_vserver.assert_has_calls(
                [mock.call(share_server='dst_srv'),
                 mock.call(share_server=fake.SHARE_SERVER)])
            mock_fpolicy_status.assert_called_once()
            mock_reusable_fpolicy.assert_called_once_with(
                dst_instance, mock_dest_client,
                fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
                fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
                fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS
            )
        else:
            self.library._get_vserver.assert_called_once_with(
                share_server=fake.SHARE_SERVER)

    def test_migration_check_compatibility_destination_type_is_encrypted(self):
        self.library._have_cluster_creds = True
        mock_dm = mock.Mock()
        self.mock_object(data_motion, 'DataMotionSession',
                         mock.Mock(return_value=mock_dm))
        self.mock_object(self.library, 'is_flexgroup_destination_host',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_is_flexgroup_pool',
                         mock.Mock(return_value=False))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(data_motion, 'get_backend_configuration')
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(share_utils, 'extract_host', mock.Mock(
            side_effect=[
                'destination_backend', 'destination_pool', 'source_pool']))
        mock_move_check = self.mock_object(self.client, 'check_volume_move')
        self.mock_object(self.library, '_get_dest_flexvol_encryption_value',
                         mock.Mock(return_value=True))
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={'spec1': 'spec-data'}))
        self.mock_object(self.library,
                         '_check_extra_specs_validity')
        self.mock_object(self.library,
                         '_check_aggregate_extra_specs_validity')
        self.mock_object(self.library, '_get_provisioning_options',
                         mock.Mock(return_value={}))
        self.mock_object(self.library, '_get_normalized_qos_specs')
        self.mock_object(self.library,
                         'validate_provisioning_options_for_share')

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
        self.assertDictEqual(expected_compatibility, migration_compatibility)
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
            cutover_action='wait', encrypt_destination=False)

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
            cutover_action='wait', encrypt_destination=True)

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
        self.assertDictEqual(expected_progress, migration_progress)
        mock_info_log.assert_called_once()

    @ddt.data({'state': 'failed'},
              {'state': 'healthy'})
    @ddt.unpack
    def test_migration_cancel(self, state):
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        self.library.configuration.netapp_migration_cancel_timeout = 15
        mock_info_log = self.mock_object(lib_base.LOG, 'info')

        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(self.client, 'abort_volume_move')
        self.mock_object(self.client, 'get_volume_move_status',
                         mock.Mock(return_value={'state': state}))

        if state == 'failed':
            retval = self.library.migration_cancel(
                self.context, fake_share.fake_share_instance(),
                fake_share.fake_share_instance(), source_snapshots,
                snapshot_mappings, share_server=fake.SHARE_SERVER,
                destination_share_server='dst_srv')

            self.assertIsNone(retval)
            mock_info_log.assert_called_once()
        else:
            self.assertRaises(
                (exception.NetAppException),
                self.library.migration_cancel, self.context,
                fake_share.fake_share_instance(),
                fake_share.fake_share_instance, source_snapshots,
                snapshot_mappings, share_server=fake.SHARE_SERVER,
                destination_share_server='dst_srv')

    @ddt.data({'already_canceled': True, 'effect': exception.NetAppException},
              {'already_canceled': False, 'effect':
                  (None, exception.NetAppException)})
    @ddt.unpack
    def test_migration_cancel_exception_volume_status(self, already_canceled,
                                                      effect):
        source_snapshots = mock.Mock()
        snapshot_mappings = mock.Mock()
        self.library.configuration.netapp_migration_cancel_timeout = 1
        mock_exception_log = self.mock_object(lib_base.LOG, 'exception')
        mock_info_log = self.mock_object(lib_base.LOG, 'info')
        self.mock_object(self.library, '_get_vserver',
                         mock.Mock(return_value=(fake.VSERVER1, mock.Mock())))
        self.mock_object(self.library, '_get_backend_share_name',
                         mock.Mock(return_value=fake.SHARE_NAME))
        self.mock_object(self.client, 'abort_volume_move')
        self.mock_object(self.client, 'get_volume_move_status',
                         mock.Mock(side_effect=effect))
        self.library.migration_cancel(
            self.context, fake_share.fake_share_instance(),
            fake_share.fake_share_instance(), source_snapshots,
            snapshot_mappings, share_server=fake.SHARE_SERVER,
            destination_share_server='dst_srv')

        mock_exception_log.assert_called_once()
        if not already_canceled:
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

    @ddt.data({'phase': 'cutover_hard_deferred',
               'provisioning_options': fake.PROVISIONING_OPTIONS_WITH_QOS,
               'policy_group_name': fake.QOS_POLICY_GROUP_NAME},
              {'phase': 'cutover_soft_deferred',
               'provisioning_options': fake.PROVISIONING_OPTIONS_WITH_QOS,
               'policy_group_name': fake.QOS_POLICY_GROUP_NAME},
              {'phase': 'completed',
               'provisioning_options': fake.PROVISIONING_OPTIONS,
               'policy_group_name': False},
              {'phase': 'completed',
               'provisioning_options': fake.PROVISIONING_OPTIONS_WITH_FPOLICY,
               'policy_group_name': False})
    @ddt.unpack
    def test_migration_complete(self, phase, provisioning_options,
                                policy_group_name):
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
        self.mock_object(self.library, '_check_fpolicy_file_operations')
        self.mock_object(
            self.library, '_get_provisioning_options',
            mock.Mock(return_value=provisioning_options))
        self.mock_object(
            self.library, '_modify_or_create_qos_for_existing_share',
            mock.Mock(return_value=policy_group_name))
        self.mock_object(vserver_client, 'modify_volume')
        mock_create_new_fpolicy = self.mock_object(
            self.library, '_create_fpolicy_for_share')

        mock_delete_policy = self.mock_object(self.library,
                                              '_delete_fpolicy_for_share')

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
            dest_aggr, 'new_share_name', **provisioning_options)
        mock_info_log.assert_called_once()
        mock_delete_policy.assert_called_once_with(src_share, fake.VSERVER1,
                                                   vserver_client)
        if phase != 'completed':
            self.assertEqual(2, mock_warning_log.call_count)
            self.assertFalse(mock_debug_log.called)
            self.assertEqual(4, mock_move_status_check.call_count)
        else:
            self.assertFalse(mock_warning_log.called)
            mock_debug_log.assert_called_once()
            mock_move_status_check.assert_called_once()
        if provisioning_options.get(
                'fpolicy_extensions_to_include') is not None:
            mock_create_new_fpolicy.assert_called_once_with(
                dest_share, fake.VSERVER1, vserver_client,
                **provisioning_options)
        else:
            mock_create_new_fpolicy.assert_not_called()

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
            share_obj, fake.VSERVER1, {'maxiops': '3000'},
            vserver_client=vserver_client)

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
                share_obj, fake.VSERVER1, {'maxiops': '3000'},
                vserver_client=vserver_client)
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

    @ddt.data('default', 'hidden', 'visible')
    def test_get_backend_info(self, snapdir):

        self.library.configuration.netapp_reset_snapdir_visibility = snapdir
        expected = {'snapdir_visibility': snapdir}

        result = self.library.get_backend_info(self.context)
        self.assertEqual(expected, result)

    @ddt.data('default', 'hidden')
    def test_ensure_shares(self, snapdir_cfg):
        shares = [
            fake_share.fake_share_instance(id='s-1',
                                           share_server='fake_server_1'),
            fake_share.fake_share_instance(id='s-2',
                                           share_server='fake_server_2'),
            fake_share.fake_share_instance(id='s-3',
                                           share_server='fake_server_2')
        ]

        vserver_client = mock.Mock()
        self.mock_object(
            self.library, '_get_vserver',
            mock.Mock(side_effect=[
                (fake.VSERVER1, vserver_client),
                (fake.VSERVER2, vserver_client),
                (fake.VSERVER2, vserver_client)
            ]))
        (self.library.configuration.
         netapp_reset_snapdir_visibility) = snapdir_cfg

        self.library.ensure_shares(self.context, shares)

        if snapdir_cfg == 'default':
            self.library._get_vserver.assert_not_called()
            vserver_client.set_volume_snapdir_access.assert_not_called()

        else:
            self.library._get_vserver.assert_has_calls([
                mock.call(share_server='fake_server_1'),
                mock.call(share_server='fake_server_2'),
                mock.call(share_server='fake_server_2'),
            ])

            vserver_client.set_volume_snapdir_access.assert_has_calls([
                mock.call('share_s_1', True),
                mock.call('share_s_2', True),
                mock.call('share_s_3', True),
            ])

    def test__check_volume_clone_split_completed(self):
        vserver_client = mock.Mock()
        mock_share_name = self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(return_value=fake.SHARE_NAME))
        vserver_client.check_volume_clone_split_completed.return_value = (
            fake.CDOT_SNAPSHOT_BUSY_SNAPMIRROR)

        self.library._check_volume_clone_split_completed(fake.SHARE,
                                                         vserver_client)

        mock_share_name.assert_called_once_with(fake.SHARE_ID)
        check_call = vserver_client.check_volume_clone_split_completed
        check_call.assert_called_once_with(fake.SHARE_NAME)

    @ddt.data(constants.STATUS_ACTIVE, constants.STATUS_CREATING_FROM_SNAPSHOT)
    def test_get_share_status(self, status):
        mock_update_from_snap = self.mock_object(
            self.library, '_update_create_from_snapshot_status')
        fake.SHARE['status'] = status

        self.library.get_share_status(fake.SHARE, fake.SHARE_SERVER)

        if status == constants.STATUS_CREATING_FROM_SNAPSHOT:
            mock_update_from_snap.assert_called_once_with(fake.SHARE,
                                                          fake.SHARE_SERVER)
        else:
            mock_update_from_snap.assert_not_called()

    def test_volume_rehost(self):
        mock_share_name = self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(return_value=fake.SHARE_NAME))
        mock_rehost = self.mock_object(self.client, 'rehost_volume')

        self.library.volume_rehost(fake.SHARE, fake.VSERVER1, fake.VSERVER2)

        mock_share_name.assert_called_once_with(fake.SHARE_ID)
        mock_rehost.assert_called_once_with(fake.SHARE_NAME, fake.VSERVER1,
                                            fake.VSERVER2)

    def test__rehost_and_mount_volume(self):
        mock_share_name = self.mock_object(
            self.library, '_get_backend_share_name',
            mock.Mock(return_value=fake.SHARE_NAME))
        mock_rehost = self.mock_object(self.library, 'volume_rehost',
                                       mock.Mock())
        src_vserver_client = mock.Mock()
        mock_unmount = self.mock_object(src_vserver_client, 'unmount_volume')
        dst_vserver_client = mock.Mock()
        mock_mount = self.mock_object(dst_vserver_client, 'mount_volume')

        self.library._rehost_and_mount_volume(
            fake.SHARE, fake.VSERVER1, src_vserver_client, fake.VSERVER2,
            dst_vserver_client)

        mock_share_name.assert_called_once_with(fake.SHARE_ID)
        mock_unmount.assert_called_once_with(fake.SHARE_NAME)
        mock_rehost.assert_called_once_with(fake.SHARE, fake.VSERVER1,
                                            fake.VSERVER2)
        mock_mount.assert_called_once_with(fake.SHARE_NAME)

    def test__move_volume_after_splitting(self):
        src_share = fake_share.fake_share_instance(id='source-share-instance')
        dest_share = fake_share.fake_share_instance(id='dest-share-instance')
        cutover_action = 'defer'
        self.library.configuration.netapp_start_volume_move_timeout = 15

        self.mock_object(time, 'sleep')
        mock_warning_log = self.mock_object(lib_base.LOG, 'warning')
        mock_vol_move = self.mock_object(self.library, '_move_volume')

        self.library._move_volume_after_splitting(
            src_share, dest_share, share_server=fake.SHARE_SERVER,
            cutover_action=cutover_action)

        mock_vol_move.assert_called_once_with(src_share, dest_share,
                                              fake.SHARE_SERVER,
                                              cutover_action)
        self.assertEqual(0, mock_warning_log.call_count)

    def test__move_volume_after_splitting_timeout(self):
        src_share = fake_share.fake_share_instance(id='source-share-instance')
        dest_share = fake_share.fake_share_instance(id='dest-share-instance')
        self.library.configuration.netapp_start_volume_move_timeout = 15
        cutover_action = 'defer'

        self.mock_object(time, 'sleep')
        mock_warning_log = self.mock_object(lib_base.LOG, 'warning')
        undergoing_split_op_msg = (
            'The volume is undergoing a clone split operation.')
        na_api_error = netapp_api.NaApiError(code=netapp_api.EAPIERROR,
                                             message=undergoing_split_op_msg)
        mock_move_vol = self.mock_object(
            self.library, '_move_volume', mock.Mock(side_effect=na_api_error))

        self.assertRaises(exception.NetAppException,
                          self.library._move_volume_after_splitting,
                          src_share, dest_share,
                          share_server=fake.SHARE_SERVER,
                          cutover_action=cutover_action)

        self.assertEqual(3, mock_move_vol.call_count)
        self.assertEqual(3, mock_warning_log.call_count)

    def test__move_volume_after_splitting_api_not_found(self):
        src_share = fake_share.fake_share_instance(id='source-share-instance')
        dest_share = fake_share.fake_share_instance(id='dest-share-instance')
        self.library.configuration.netapp_start_volume_move_timeout = 15
        cutover_action = 'defer'

        self.mock_object(time, 'sleep')
        mock_warning_log = self.mock_object(lib_base.LOG, 'warning')
        na_api_error = netapp_api.NaApiError(code=netapp_api.EOBJECTNOTFOUND)
        mock_move_vol = self.mock_object(
            self.library, '_move_volume', mock.Mock(side_effect=na_api_error))

        self.assertRaises(exception.NetAppException,
                          self.library._move_volume_after_splitting,
                          src_share, dest_share,
                          share_server=fake.SHARE_SERVER,
                          cutover_action=cutover_action)

        mock_move_vol.assert_called_once_with(src_share, dest_share,
                                              fake.SHARE_SERVER,
                                              cutover_action)
        mock_warning_log.assert_not_called()

    @ddt.data({'total': 20, 'free': 5, 'reserved': 10, 'thin': False,
               'over_sub': 0, 'size': 3, 'compatible': True, 'nb_pools': 1},
              {'total': 20, 'free': 5, 'reserved': 10, 'thin': False,
               'over_sub': 0, 'size': 4, 'compatible': False, 'nb_pools': 1},
              {'total': 20, 'free': 5, 'reserved': 20, 'thin': False,
               'over_sub': 1.1, 'size': 3, 'compatible': False, 'nb_pools': 1},
              {'total': 20, 'free': 5, 'reserved': 10, 'thin': True,
               'over_sub': 2.0, 'size': 6, 'compatible': True, 'nb_pools': 1},
              {'total': 20, 'free': 5, 'reserved': 10, 'thin': True,
               'over_sub': 1.0, 'size': 4, 'compatible': False, 'nb_pools': 1},
              {'total': 'unknown', 'free': 5, 'reserved': 0, 'thin': False,
               'over_sub': 3.0, 'size': 1, 'compatible': False, 'nb_pools': 1},
              {'total': 20, 'free': 5, 'reserved': 10, 'thin': True,
               'over_sub': 1.0, 'size': 6, 'compatible': True, 'nb_pools': 2},
              {'total': 20, 'free': 5, 'reserved': 10, 'thin': True,
               'over_sub': 1.0, 'size': 7, 'compatible': False, 'nb_pools': 2},
              )
    @ddt.unpack
    def test__check_capacity_compatibility(self, total, free, reserved, thin,
                                           over_sub, size, compatible,
                                           nb_pools):
        pools = []
        for p in range(nb_pools):
            pool = copy.deepcopy(fake.POOLS[0])
            pool['total_capacity_gb'] = total
            pool['free_capacity_gb'] = free
            pool['reserved_percentage'] = reserved
            pool['max_over_subscription_ratio'] = over_sub
            pools.append(pool)

        result = self.library._check_capacity_compatibility(pools, thin, size)

        self.assertEqual(compatible, result)

    @ddt.data({'provisioning_opts': fake.PROVISIONING_OPTS_WITH_ADAPT_QOS,
               'qos_specs': {fake.QOS_NORMALIZED_SPEC: 3000},
               'extra_specs': None,
               'cluster_credentials': True},
              {'provisioning_opts': fake.PROVISIONING_OPTS_WITH_ADAPT_QOS,
               'qos_specs': None,
               'extra_specs': fake.EXTRA_SPEC_WITH_REPLICATION,
               'cluster_credentials': True},
              {'provisioning_opts': fake.PROVISIONING_OPTIONS,
               'qos_specs': {fake.QOS_NORMALIZED_SPEC: 3000},
               'extra_specs': None,
               'cluster_credentials': False},
              {'provisioning_opts': fake.PROVISIONING_OPTS_WITH_ADAPT_QOS,
               'qos_specs': None,
               'extra_specs': None,
               'cluster_credentials': False},
              {'provisioning_opts': fake.PROVISIONING_OPTIONS_INVALID_FPOLICY,
               'qos_specs': None,
               'extra_specs': None,
               'cluster_credentials': False},
              {'provisioning_opts': fake.PROVISIONING_OPTIONS_WITH_FPOLICY,
               'qos_specs': None,
               'extra_specs': {'replication_type': 'dr'},
               'cluster_credentials': False}
              )
    @ddt.unpack
    def test_validate_provisioning_options_for_share_invalid_params(
            self, provisioning_opts, qos_specs, extra_specs,
            cluster_credentials):
        self.library._have_cluster_creds = cluster_credentials

        self.assertRaises(exception.NetAppException,
                          self.library.validate_provisioning_options_for_share,
                          provisioning_opts, extra_specs=extra_specs,
                          qos_specs=qos_specs)

    def test__get_backend_fpolicy_policy_name(self):
        result = self.library._get_backend_fpolicy_policy_name(
            fake.SHARE_ID)
        expected = 'fpolicy_policy_' + fake.SHARE_ID.replace('-', '_')

        self.assertEqual(expected, result)

    def test__get_backend_fpolicy_event_name(self):
        result = self.library._get_backend_fpolicy_event_name(
            fake.SHARE_ID, 'NFS')
        expected = 'fpolicy_event_nfs_' + fake.SHARE_ID.replace('-', '_')

        self.assertEqual(expected, result)

    @ddt.data({},
              {'policy-name': fake.FPOLICY_POLICY_NAME,
               'shares-to-include': [fake.SHARE_NAME]})
    def test__create_fpolicy_for_share(self, reusable_scope):
        vserver_client = mock.Mock()
        vserver_name = fake.VSERVER1
        new_fake_share = copy.deepcopy(fake.SHARE)
        new_fake_share['id'] = 'new_fake_id'
        new_fake_share['share_proto'] = 'CIFS'
        event_name = 'fpolicy_event_cifs_new_fake_id'
        events = [event_name]
        policy_name = 'fpolicy_policy_new_fake_id'
        shares_to_include = []
        if reusable_scope:
            shares_to_include = copy.deepcopy(
                reusable_scope.get('shares-to-include'))
            shares_to_include.append('share_new_fake_id')

        mock_reusable_scope = self.mock_object(
            self.library, '_find_reusable_fpolicy_scope',
            mock.Mock(return_value=reusable_scope))
        mock_modify_policy = self.mock_object(
            vserver_client, 'modify_fpolicy_scope')
        mock_get_policies = self.mock_object(
            vserver_client, 'get_fpolicy_policies_status',
            mock.Mock(return_value=[]))
        mock_create_event = self.mock_object(
            vserver_client, 'create_fpolicy_event')
        mock_enable_fpolicy = self.mock_object(
            vserver_client, 'enable_fpolicy_policy')
        mock_create_fpolicy_policy_with_scope = self.mock_object(
            vserver_client, 'create_fpolicy_policy_with_scope')

        self.library._create_fpolicy_for_share(
            new_fake_share, vserver_name, vserver_client,
            fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
            fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS)

        mock_reusable_scope.assert_called_once_with(
            new_fake_share, vserver_client,
            fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
            fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS)

        if reusable_scope:
            mock_modify_policy.assert_called_once_with(
                'share_new_fake_id', fake.FPOLICY_POLICY_NAME,
                shares_to_include=shares_to_include)
            mock_get_policies.assert_not_called()
            mock_create_event.assert_not_called()
            mock_create_fpolicy_policy_with_scope.assert_not_called()
            mock_enable_fpolicy.assert_not_called()
        else:
            mock_modify_policy.assert_not_called()

            mock_get_policies.assert_called_once()
            mock_create_event.assert_called_once_with(
                'share_new_fake_id',
                event_name, new_fake_share['share_proto'].lower(),
                fake.FPOLICY_FILE_OPERATIONS_LIST)
            mock_create_fpolicy_policy_with_scope.assert_called_once_with(
                policy_name, 'share_new_fake_id', events,
                extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
                extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE
            )
            mock_enable_fpolicy.assert_called_once_with(
                'share_new_fake_id', policy_name, 1)

    def test__create_fpolicy_for_share_max_policies_error(self):
        fake_client = mock.Mock()
        vserver_name = fake.VSERVER1
        mock_reusable_scope = self.mock_object(
            self.library, '_find_reusable_fpolicy_scope',
            mock.Mock(return_value=None))
        policies = [
            x for x in range(1, self.library.FPOLICY_MAX_VSERVER_POLICIES + 1)]
        mock_get_policies = self.mock_object(
            fake_client, 'get_fpolicy_policies_status',
            mock.Mock(return_value=policies))

        self.assertRaises(
            exception.NetAppException,
            self.library._create_fpolicy_for_share,
            fake.SHARE, vserver_name, fake_client,
            fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
            fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS)

        mock_reusable_scope.assert_called_once_with(
            fake.SHARE, fake_client,
            fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
            fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS)
        mock_get_policies.assert_called_once()

    def test__create_fpolicy_for_share_client_error(self):
        fake_client = mock.Mock()
        vserver_name = fake.VSERVER1
        new_fake_share = copy.deepcopy(fake.SHARE)
        new_fake_share['id'] = 'new_fake_id'
        new_fake_share['share_proto'] = 'CIFS'
        event_name = 'fpolicy_event_cifs_new_fake_id'
        events = [event_name]
        policy_name = 'fpolicy_policy_new_fake_id'

        mock_reusable_scope = self.mock_object(
            self.library, '_find_reusable_fpolicy_scope',
            mock.Mock(return_value=None))
        mock_get_policies = self.mock_object(
            fake_client, 'get_fpolicy_policies_status',
            mock.Mock(return_value=[]))
        mock_create_event = self.mock_object(
            fake_client, 'create_fpolicy_event')
        mock_create_fpolicy_policy_with_scope = self.mock_object(
            fake_client, 'create_fpolicy_policy_with_scope',
            mock.Mock(side_effect=self._mock_api_error()))
        mock_delete_fpolicy = self.mock_object(
            fake_client, 'delete_fpolicy_policy')
        mock_delete_event = self.mock_object(
            fake_client, 'delete_fpolicy_event')

        self.assertRaises(
            exception.NetAppException,
            self.library._create_fpolicy_for_share,
            new_fake_share, vserver_name, fake_client,
            fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
            fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS)

        mock_reusable_scope.assert_called_once_with(
            new_fake_share, fake_client,
            fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
            fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS)
        mock_get_policies.assert_called_once()
        mock_create_event.assert_called_once_with(
            'share_new_fake_id', event_name,
            new_fake_share['share_proto'].lower(),
            fake.FPOLICY_FILE_OPERATIONS_LIST)
        mock_create_fpolicy_policy_with_scope.assert_called_once_with(
            policy_name, 'share_new_fake_id', events,
            extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE)
        mock_delete_fpolicy.assert_called_once_with(
            'share_new_fake_id', policy_name)
        mock_delete_event.assert_called_once_with(
            'share_new_fake_id', event_name)

    def test__find_reusable_fpolicy_scope(self):
        vserver_client = mock.Mock()
        new_fake_share = copy.deepcopy(fake.SHARE)
        new_fake_share['share_proto'] = 'CIFS'
        reusable_scopes = [{
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'file-extensions-to-include': fake.FPOLICY_EXT_TO_INCLUDE_LIST,
            'file-extensions-to-exclude': fake.FPOLICY_EXT_TO_EXCLUDE_LIST,
            'shares-to-include': ['any_other_fake_share'],
        }]
        reusable_policies = [{
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'engine-name': fake.FPOLICY_ENGINE,
            'events': [fake.FPOLICY_EVENT_NAME]
        }]
        reusable_events = [{
            'event-name': fake.FPOLICY_EVENT_NAME,
            'protocol': new_fake_share['share_proto'].lower(),
            'file-operations': fake.FPOLICY_FILE_OPERATIONS_LIST
        }]
        mock_get_scopes = self.mock_object(
            vserver_client, 'get_fpolicy_scopes',
            mock.Mock(return_value=reusable_scopes))
        mock_get_policies = self.mock_object(
            vserver_client, 'get_fpolicy_policies',
            mock.Mock(return_value=reusable_policies))
        mocke_get_events = self.mock_object(
            vserver_client, 'get_fpolicy_events',
            mock.Mock(return_value=reusable_events)
        )

        result = self.library._find_reusable_fpolicy_scope(
            new_fake_share, vserver_client,
            fpolicy_extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            fpolicy_extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
            fpolicy_file_operations=fake.FPOLICY_FILE_OPERATIONS)

        self.assertEqual(reusable_scopes[0], result)

        mock_get_scopes.assert_called_once_with(
            share_name=fake.SHARE_NAME,
            extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
            shares_to_include=None)
        mock_get_policies.assert_called_once_with(
            share_name=fake.SHARE_NAME,
            policy_name=fake.FPOLICY_POLICY_NAME)
        mocke_get_events.assert_called_once_with(
            share_name=fake.SHARE_NAME,
            event_name=fake.FPOLICY_EVENT_NAME)

    @ddt.data(False, True)
    def test__delete_fpolicy_for_share(self, last_share):
        fake_vserver_client = mock.Mock()
        fake_vserver_name = fake.VSERVER1
        fake_share = copy.deepcopy(fake.SHARE)
        share_name = self.library._get_backend_share_name(fake.SHARE_ID)
        existing_shares = [share_name]
        if not last_share:
            existing_shares.append('any_other_share')
        scopes = [{
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'file-extensions-to-include': fake.FPOLICY_EXT_TO_INCLUDE_LIST,
            'file-extensions-to-exclude': fake.FPOLICY_EXT_TO_EXCLUDE_LIST,
            'shares-to-include': existing_shares,
        }]
        shares_to_include = copy.copy(scopes[0].get('shares-to-include'))
        shares_to_include.remove(share_name)
        policies = [{
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'engine-name': fake.FPOLICY_ENGINE,
            'events': [fake.FPOLICY_EVENT_NAME]
        }]

        mock_get_scopes = self.mock_object(
            fake_vserver_client, 'get_fpolicy_scopes',
            mock.Mock(return_value=scopes))
        mock_modify_scope = self.mock_object(
            fake_vserver_client, 'modify_fpolicy_scope')

        mock_disable_policy = self.mock_object(
            fake_vserver_client, 'disable_fpolicy_policy')
        mock_get_policies = self.mock_object(
            fake_vserver_client, 'get_fpolicy_policies',
            mock.Mock(return_value=policies))
        mock_delete_scope = self.mock_object(
            fake_vserver_client, 'delete_fpolicy_scope')
        mock_delete_policy = self.mock_object(
            fake_vserver_client, 'delete_fpolicy_policy')
        mock_delete_event = self.mock_object(
            fake_vserver_client, 'delete_fpolicy_event')

        self.library._delete_fpolicy_for_share(fake_share, fake_vserver_name,
                                               fake_vserver_client)

        mock_get_scopes.assert_called_once_with(
            share_name=fake.SHARE_NAME,
            shares_to_include=[share_name])
        if shares_to_include:
            mock_modify_scope.assert_called_once_with(
                fake.SHARE_NAME,
                fake.FPOLICY_POLICY_NAME, shares_to_include=shares_to_include)
        else:
            mock_disable_policy.assert_called_once_with(
                fake.FPOLICY_POLICY_NAME)
            mock_get_policies.assert_called_once_with(
                share_name=fake.SHARE_NAME,
                policy_name=fake.FPOLICY_POLICY_NAME)
            mock_delete_scope.assert_called_once_with(
                fake.FPOLICY_POLICY_NAME)
            mock_delete_policy.assert_called_once_with(
                fake.SHARE_NAME,
                fake.FPOLICY_POLICY_NAME)
            mock_delete_event.assert_called_once_with(
                fake.FPOLICY_EVENT_NAME)

    @ddt.data(True, False)
    def test_initialize_flexgroup_pools(self, auto_provision):
        self.library.configuration.netapp_enable_flexgroup = True
        pool = None if auto_provision else [fake.FLEXGROUP_POOL_OPT_RAW]
        mock_safe_get = self.mock_object(
            self.library.configuration, 'safe_get',
            mock.Mock(return_value=pool))
        mock_is_flex_support = self.mock_object(
            self.library._client, 'is_flexgroup_supported',
            mock.Mock(return_value=True))
        mock_parse = self.mock_object(
            na_utils, 'parse_flexgroup_pool_config',
            mock.Mock(return_value=fake.FLEXGROUP_POOL_OPT))
        aggr_set = set(fake.FLEXGROUP_POOL_AGGR)

        self.library._initialize_flexgroup_pools(aggr_set)

        mock_safe_get.assert_called_once_with('netapp_flexgroup_pools')
        mock_is_flex_support.assert_called_once_with()
        if auto_provision:
            self.assertEqual(self.library._flexgroup_pools,
                             {na_utils.FLEXGROUP_DEFAULT_POOL_NAME: sorted(
                                 aggr_set)})
            self.assertTrue(self.library._is_flexgroup_auto)
            mock_parse.assert_not_called()
        else:
            self.assertEqual(self.library._flexgroup_pools,
                             fake.FLEXGROUP_POOL_OPT)
            self.assertFalse(self.library._is_flexgroup_auto)
            mock_parse.assert_called_once_with(
                [fake.FLEXGROUP_POOL_OPT_RAW],
                cluster_aggr_set=set(fake.FLEXGROUP_POOL_AGGR), check=True)

    def test_initialize_flexgroup_pools_no_opt(self):
        self.library.configuration.netapp_enable_flexgroup = False
        self.mock_object(self.library.configuration,
                         'safe_get',
                         mock.Mock(return_value=None))

        self.library._initialize_flexgroup_pools(set(fake.FLEXGROUP_POOL_AGGR))

        self.assertEqual(self.library._flexgroup_pools, {})

    def test_initialize_flexgroup_pools_raise_version(self):
        self.library.configuration.netapp_enable_flexgroup = True
        self.mock_object(self.library.configuration,
                         'safe_get',
                         mock.Mock(return_value=[fake.FLEXGROUP_POOL_OPT_RAW]))
        self.mock_object(self.library._client,
                         'is_flexgroup_supported',
                         mock.Mock(return_value=False))

        self.assertRaises(exception.NetAppException,
                          self.library._initialize_flexgroup_pools,
                          set(fake.FLEXGROUP_POOL_AGGR))

    def test_initialize_flexgroup_pools_raise_no_enable_with_pool(self):
        self.library.configuration.netapp_enable_flexgroup = False
        self.mock_object(self.library.configuration,
                         'safe_get',
                         mock.Mock(return_value=[fake.FLEXGROUP_POOL_OPT_RAW]))

        self.assertRaises(exception.NetAppException,
                          self.library._initialize_flexgroup_pools,
                          set(fake.FLEXGROUP_POOL_AGGR))

    @ddt.data(True, False)
    def test_get_flexgroup_pool_name(self, auto_provisioned):

        self.library._is_flexgroup_auto = auto_provisioned
        self.library._flexgroup_pools = fake.FLEXGROUP_POOL_OPT

        result = self.library._get_flexgroup_pool_name(
            fake.FLEXGROUP_POOL_AGGR)

        if auto_provisioned:
            self.assertEqual(na_utils.FLEXGROUP_DEFAULT_POOL_NAME, result)
        else:
            self.assertEqual(fake.FLEXGROUP_POOL_NAME, result)

    def test_get_flexgroup_pool_name_not_found(self):

        self.library._is_flexgroup_auto = False
        self.library._flexgroup_pools = fake.FLEXGROUP_POOL_OPT

        result = self.library._get_flexgroup_pool_name([])

        self.assertEqual('', result)

    def test_is_flexgroup_pool(self):

        self.library._flexgroup_pools = fake.FLEXGROUP_POOL_OPT

        result = self.library._is_flexgroup_pool(fake.FLEXGROUP_POOL_NAME)

        self.assertTrue(result)

    @ddt.data({'pool_name': fake.FLEXGROUP_POOL_NAME,
               'aggr_list': fake.FLEXGROUP_POOL_AGGR},
              {'pool_name': '',
               'aggr_list': []})
    @ddt.unpack
    def test_get_flexgroup_aggregate_list(self, pool_name, aggr_list):

        self.library._flexgroup_pools = fake.FLEXGROUP_POOL_OPT

        result = self.library._get_flexgroup_aggregate_list(pool_name)

        self.assertEqual(aggr_list, result)

    def test_is_flexgroup_share(self):
        vserver_client = mock.Mock()
        vserver_client.is_flexgroup_volume.return_value = True

        result = self.library._is_flexgroup_share(vserver_client,
                                                  fake.SHARE_NAME)

        vserver_client.is_flexgroup_volume.assert_called_once_with(
            fake.SHARE_NAME)
        self.assertTrue(result)

    def test_is_flexgroup_share_raise(self):
        vserver_client = mock.Mock()
        vserver_client.is_flexgroup_volume.side_effect = (
            exception.NetAppException)

        self.assertRaises(exception.ShareNotFound,
                          self.library._is_flexgroup_share,
                          vserver_client, fake.SHARE_NAME)

        vserver_client.is_flexgroup_volume.assert_called_once_with(
            fake.SHARE_NAME)

    @ddt.data(
        {'enabled': True, 'flexgroup_only': False, 'is_flexvol': True},
        {'enabled': False, 'flexgroup_only': False, 'is_flexvol': True},
        {'enabled': True, 'flexgroup_only': True, 'is_flexvol': False},
        {'enabled': False, 'flexgroup_only': True, 'is_flexvol': True})
    @ddt.unpack
    def test_is_flexvol_pool_configured(self, enabled, flexgroup_only,
                                        is_flexvol):

        self.library.configuration.netapp_enable_flexgroup = enabled
        self.library.configuration.netapp_flexgroup_pool_only = flexgroup_only

        result = self.library.is_flexvol_pool_configured()

        self.assertEqual(is_flexvol, result)

    def test_get_minimum_flexgroup_size(self):
        self.mock_object(self.library, '_get_flexgroup_aggregate_list',
                         mock.Mock(return_value=fake.AGGREGATES))

        result = self.library._get_minimum_flexgroup_size(fake.POOL_NAME)

        expected = (len(fake.AGGREGATES) *
                    self.library.FLEXGROUP_MIN_SIZE_PER_AGGR)
        self.assertEqual(expected, result)
        self.library._get_flexgroup_aggregate_list.assert_called_once_with(
            fake.POOL_NAME)

    def test_is_flexgroup_destination_host_not_enabled(self):
        mock_config = mock.Mock()
        dm_session = mock.Mock()
        mock_get_backend = self.mock_object(
            dm_session, 'get_backend_name_and_config_obj',
            mock.Mock(return_value=('fake', mock_config)))
        mock_safe_get = self.mock_object(
            mock_config, 'safe_get', mock.Mock(return_value=False))

        result = self.library.is_flexgroup_destination_host(fake.HOST_NAME,
                                                            dm_session)

        self.assertFalse(result)
        mock_get_backend.assert_called_once_with(fake.HOST_NAME)
        mock_safe_get.assert_called_once_with('netapp_enable_flexgroup')

    @ddt.data(None, [{'fg1': fake.AGGREGATE}])
    def test_is_flexgroup_destination_host_false(self, flexgroup_pools):
        mock_config = mock.Mock()
        dm_session = mock.Mock()
        mock_get_backend = self.mock_object(
            dm_session, 'get_backend_name_and_config_obj',
            mock.Mock(return_value=('fake', mock_config)))
        mock_safe_get = self.mock_object(
            mock_config, 'safe_get',
            mock.Mock(side_effect=[True, flexgroup_pools]))
        mock_extract = self.mock_object(
            share_utils, 'extract_host',
            mock.Mock(return_value=fake.POOL_NAME))
        mock_parse = self.mock_object(
            na_utils, 'parse_flexgroup_pool_config',
            mock.Mock(return_value={}))

        result = self.library.is_flexgroup_destination_host(fake.HOST_NAME,
                                                            dm_session)

        self.assertFalse(result)
        mock_get_backend.assert_called_once_with(fake.HOST_NAME)
        mock_safe_get.assert_has_calls([
            mock.call('netapp_enable_flexgroup'),
            mock.call('netapp_flexgroup_pools'),
        ])
        mock_extract.assert_called_once_with(fake.HOST_NAME, level='pool')
        if flexgroup_pools:
            mock_parse.assert_called_once_with(flexgroup_pools)
        else:
            mock_parse.assert_not_called()

    def test_is_flexgroup_destination_host_true(self):
        flexgroup_pools = [{fake.POOL_NAME: fake.AGGREGATE}]
        mock_config = mock.Mock()
        dm_session = mock.Mock()
        mock_get_backend = self.mock_object(
            dm_session, 'get_backend_name_and_config_obj',
            mock.Mock(return_value=('fake', mock_config)))
        mock_safe_get = self.mock_object(
            mock_config, 'safe_get',
            mock.Mock(side_effect=[True, flexgroup_pools]))
        mock_extract = self.mock_object(
            share_utils, 'extract_host',
            mock.Mock(return_value=fake.POOL_NAME))
        mock_parse = self.mock_object(
            na_utils, 'parse_flexgroup_pool_config',
            mock.Mock(return_value=flexgroup_pools[0]))

        result = self.library.is_flexgroup_destination_host(fake.HOST_NAME,
                                                            dm_session)

        self.assertTrue(result)
        mock_get_backend.assert_called_once_with(fake.HOST_NAME)
        mock_safe_get.assert_has_calls([
            mock.call('netapp_enable_flexgroup'),
            mock.call('netapp_flexgroup_pools'),
        ])
        mock_extract.assert_called_once_with(fake.HOST_NAME, level='pool')
        mock_parse.assert_called_once_with(flexgroup_pools)
