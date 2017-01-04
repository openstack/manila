# Copyright (c) 2016 Clinton Knight
# All rights reserved.
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

import ddt
import mock

from manila import exception
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.cluster_mode import performance
from manila import test
from manila.tests.share.drivers.netapp.dataontap import fakes as fake


@ddt.ddt
class PerformanceLibraryTestCase(test.TestCase):

    def setUp(self):
        super(PerformanceLibraryTestCase, self).setUp()

        with mock.patch.object(performance.PerformanceLibrary,
                               '_init_counter_info'):
            self.zapi_client = mock.Mock()
            self.perf_library = performance.PerformanceLibrary(
                self.zapi_client)
            self.perf_library.system_object_name = 'system'
            self.perf_library.avg_processor_busy_base_counter_name = (
                'cpu_elapsed_time1')

        self._set_up_fake_pools()

    def _set_up_fake_pools(self):

        self.fake_volumes = {
            'pool1': {
                'netapp_aggregate': 'aggr1',
            },
            'pool2': {
                'netapp_aggregate': 'aggr2',
            },
            'pool3': {
                'netapp_aggregate': 'aggr2',
            },
        }
        self.fake_aggregates = {
            'pool4': {
                'netapp_aggregate': 'aggr3',
            }
        }

        self.fake_aggr_names = ['aggr1', 'aggr2', 'aggr3']
        self.fake_nodes = ['node1', 'node2']
        self.fake_aggr_node_map = {
            'aggr1': 'node1',
            'aggr2': 'node2',
            'aggr3': 'node2',
        }

    def _get_fake_counters(self):

        return {
            'node1': list(range(11, 21)),
            'node2': list(range(21, 31)),
        }

    def test_init(self):

        mock_zapi_client = mock.Mock()
        mock_init_counter_info = self.mock_object(
            performance.PerformanceLibrary, '_init_counter_info')

        library = performance.PerformanceLibrary(mock_zapi_client)

        self.assertEqual(mock_zapi_client, library.zapi_client)
        mock_init_counter_info.assert_called_once_with()

    def test_init_counter_info_not_supported(self):

        self.zapi_client.features.SYSTEM_METRICS = False
        self.zapi_client.features.SYSTEM_CONSTITUENT_METRICS = False
        mock_get_base_counter_name = self.mock_object(
            self.perf_library, '_get_base_counter_name')

        self.perf_library._init_counter_info()

        self.assertIsNone(self.perf_library.system_object_name)
        self.assertIsNone(
            self.perf_library.avg_processor_busy_base_counter_name)
        self.assertFalse(mock_get_base_counter_name.called)

    @ddt.data({
        'system_constituent': False,
        'base_counter': 'cpu_elapsed_time1',
    }, {
        'system_constituent': True,
        'base_counter': 'cpu_elapsed_time',
    })
    @ddt.unpack
    def test_init_counter_info_api_error(self, system_constituent,
                                         base_counter):

        self.zapi_client.features.SYSTEM_METRICS = True
        self.zapi_client.features.SYSTEM_CONSTITUENT_METRICS = (
            system_constituent)
        self.mock_object(self.perf_library,
                         '_get_base_counter_name',
                         mock.Mock(side_effect=netapp_api.NaApiError))

        self.perf_library._init_counter_info()

        self.assertEqual(
            base_counter,
            self.perf_library.avg_processor_busy_base_counter_name)

    def test_init_counter_info_system(self):

        self.zapi_client.features.SYSTEM_METRICS = True
        self.zapi_client.features.SYSTEM_CONSTITUENT_METRICS = False
        mock_get_base_counter_name = self.mock_object(
            self.perf_library, '_get_base_counter_name',
            mock.Mock(return_value='cpu_elapsed_time1'))

        self.perf_library._init_counter_info()

        self.assertEqual('system', self.perf_library.system_object_name)
        self.assertEqual(
            'cpu_elapsed_time1',
            self.perf_library.avg_processor_busy_base_counter_name)
        mock_get_base_counter_name.assert_called_once_with(
            'system', 'avg_processor_busy')

    def test_init_counter_info_system_constituent(self):

        self.zapi_client.features.SYSTEM_METRICS = False
        self.zapi_client.features.SYSTEM_CONSTITUENT_METRICS = True
        mock_get_base_counter_name = self.mock_object(
            self.perf_library, '_get_base_counter_name',
            mock.Mock(return_value='cpu_elapsed_time'))

        self.perf_library._init_counter_info()

        self.assertEqual('system:constituent',
                         self.perf_library.system_object_name)
        self.assertEqual(
            'cpu_elapsed_time',
            self.perf_library.avg_processor_busy_base_counter_name)
        mock_get_base_counter_name.assert_called_once_with(
            'system:constituent', 'avg_processor_busy')

    def test_update_performance_cache(self):

        self.perf_library.performance_counters = self._get_fake_counters()
        mock_get_aggregates_for_pools = self.mock_object(
            self.perf_library, '_get_aggregates_for_pools',
            mock.Mock(return_value=self.fake_aggr_names))
        mock_get_nodes_for_aggregates = self.mock_object(
            self.perf_library, '_get_nodes_for_aggregates',
            mock.Mock(return_value=(self.fake_nodes,
                                    self.fake_aggr_node_map)))
        mock_get_node_utilization_counters = self.mock_object(
            self.perf_library, '_get_node_utilization_counters',
            mock.Mock(side_effect=[21, 31]))
        mock_get_node_utilization = self.mock_object(
            self.perf_library, '_get_node_utilization',
            mock.Mock(side_effect=[25, 75]))

        self.perf_library.update_performance_cache(self.fake_volumes,
                                                   self.fake_aggregates)

        expected_performance_counters = {
            'node1': list(range(12, 22)),
            'node2': list(range(22, 32)),
        }
        self.assertEqual(expected_performance_counters,
                         self.perf_library.performance_counters)

        expected_pool_utilization = {
            'pool1': 25,
            'pool2': 75,
            'pool3': 75,
            'pool4': 75,
        }
        self.assertEqual(expected_pool_utilization,
                         self.perf_library.pool_utilization)

        mock_get_aggregates_for_pools.assert_called_once_with(
            self.fake_volumes, self.fake_aggregates)
        mock_get_nodes_for_aggregates.assert_called_once_with(
            self.fake_aggr_names)
        mock_get_node_utilization_counters.assert_has_calls([
            mock.call('node1'), mock.call('node2')])
        mock_get_node_utilization.assert_has_calls([
            mock.call(12, 21, 'node1'), mock.call(22, 31, 'node2')])

    def test_update_performance_cache_first_pass(self):

        mock_get_aggregates_for_pools = self.mock_object(
            self.perf_library, '_get_aggregates_for_pools',
            mock.Mock(return_value=self.fake_aggr_names))
        mock_get_nodes_for_aggregates = self.mock_object(
            self.perf_library, '_get_nodes_for_aggregates',
            mock.Mock(return_value=(self.fake_nodes,
                                    self.fake_aggr_node_map)))
        mock_get_node_utilization_counters = self.mock_object(
            self.perf_library, '_get_node_utilization_counters',
            mock.Mock(side_effect=[11, 21]))
        mock_get_node_utilization = self.mock_object(
            self.perf_library, '_get_node_utilization',
            mock.Mock(side_effect=[25, 75]))

        self.perf_library.update_performance_cache(self.fake_volumes,
                                                   self.fake_aggregates)

        expected_performance_counters = {'node1': [11], 'node2': [21]}
        self.assertEqual(expected_performance_counters,
                         self.perf_library.performance_counters)

        expected_pool_utilization = {
            'pool1': performance.DEFAULT_UTILIZATION,
            'pool2': performance.DEFAULT_UTILIZATION,
            'pool3': performance.DEFAULT_UTILIZATION,
            'pool4': performance.DEFAULT_UTILIZATION,
        }
        self.assertEqual(expected_pool_utilization,
                         self.perf_library.pool_utilization)

        mock_get_aggregates_for_pools.assert_called_once_with(
            self.fake_volumes, self.fake_aggregates)
        mock_get_nodes_for_aggregates.assert_called_once_with(
            self.fake_aggr_names)
        mock_get_node_utilization_counters.assert_has_calls([
            mock.call('node1'), mock.call('node2')])
        self.assertFalse(mock_get_node_utilization.called)

    def test_update_performance_cache_unknown_nodes(self):

        self.perf_library.performance_counters = self._get_fake_counters()
        mock_get_aggregates_for_pools = self.mock_object(
            self.perf_library, '_get_aggregates_for_pools',
            mock.Mock(return_value=self.fake_aggr_names))
        mock_get_nodes_for_aggregates = self.mock_object(
            self.perf_library, '_get_nodes_for_aggregates',
            mock.Mock(return_value=([], {})))
        mock_get_node_utilization_counters = self.mock_object(
            self.perf_library, '_get_node_utilization_counters',
            mock.Mock(side_effect=[11, 21]))
        mock_get_node_utilization = self.mock_object(
            self.perf_library, '_get_node_utilization',
            mock.Mock(side_effect=[25, 75]))

        self.perf_library.update_performance_cache(self.fake_volumes,
                                                   self.fake_aggregates)

        self.assertEqual(self._get_fake_counters(),
                         self.perf_library.performance_counters)

        expected_pool_utilization = {
            'pool1': performance.DEFAULT_UTILIZATION,
            'pool2': performance.DEFAULT_UTILIZATION,
            'pool3': performance.DEFAULT_UTILIZATION,
            'pool4': performance.DEFAULT_UTILIZATION,
        }
        self.assertEqual(expected_pool_utilization,
                         self.perf_library.pool_utilization)

        mock_get_aggregates_for_pools.assert_called_once_with(
            self.fake_volumes, self.fake_aggregates)
        mock_get_nodes_for_aggregates.assert_called_once_with(
            self.fake_aggr_names)
        self.assertFalse(mock_get_node_utilization_counters.called)
        self.assertFalse(mock_get_node_utilization.called)

    def test_update_performance_cache_counters_unavailable(self):

        self.perf_library.performance_counters = self._get_fake_counters()
        mock_get_aggregates_for_pools = self.mock_object(
            self.perf_library, '_get_aggregates_for_pools',
            mock.Mock(return_value=self.fake_aggr_names))
        mock_get_nodes_for_aggregates = self.mock_object(
            self.perf_library, '_get_nodes_for_aggregates',
            mock.Mock(return_value=(self.fake_nodes,
                                    self.fake_aggr_node_map)))
        mock_get_node_utilization_counters = self.mock_object(
            self.perf_library, '_get_node_utilization_counters',
            mock.Mock(side_effect=[None, None]))
        mock_get_node_utilization = self.mock_object(
            self.perf_library, '_get_node_utilization',
            mock.Mock(side_effect=[25, 75]))

        self.perf_library.update_performance_cache(self.fake_volumes,
                                                   self.fake_aggregates)

        self.assertEqual(self._get_fake_counters(),
                         self.perf_library.performance_counters)

        expected_pool_utilization = {
            'pool1': performance.DEFAULT_UTILIZATION,
            'pool2': performance.DEFAULT_UTILIZATION,
            'pool3': performance.DEFAULT_UTILIZATION,
            'pool4': performance.DEFAULT_UTILIZATION,
        }
        self.assertEqual(expected_pool_utilization,
                         self.perf_library.pool_utilization)

        mock_get_aggregates_for_pools.assert_called_once_with(
            self.fake_volumes, self.fake_aggregates)
        mock_get_nodes_for_aggregates.assert_called_once_with(
            self.fake_aggr_names)
        mock_get_node_utilization_counters.assert_has_calls([
            mock.call('node1'), mock.call('node2')])
        self.assertFalse(mock_get_node_utilization.called)

    def test_update_performance_cache_not_supported(self):

        self.zapi_client.features.SYSTEM_METRICS = False
        self.zapi_client.features.SYSTEM_CONSTITUENT_METRICS = False

        mock_get_aggregates_for_pools = self.mock_object(
            self.perf_library, '_get_aggregates_for_pools')

        self.perf_library.update_performance_cache(self.fake_volumes,
                                                   self.fake_aggregates)

        expected_performance_counters = {}
        self.assertEqual(expected_performance_counters,
                         self.perf_library.performance_counters)

        expected_pool_utilization = {}
        self.assertEqual(expected_pool_utilization,
                         self.perf_library.pool_utilization)

        self.assertFalse(mock_get_aggregates_for_pools.called)

    @ddt.data({'pool': 'pool1', 'expected': 10.0},
              {'pool': 'pool3', 'expected': performance.DEFAULT_UTILIZATION})
    @ddt.unpack
    def test_get_node_utilization_for_pool(self, pool, expected):

        self.perf_library.pool_utilization = {'pool1': 10.0, 'pool2': 15.0}

        result = self.perf_library.get_node_utilization_for_pool(pool)

        self.assertAlmostEqual(expected, result)

    def test__update_for_failover(self):
        self.mock_object(self.perf_library, 'update_performance_cache')
        mock_client = mock.Mock(name='FAKE_ZAPI_CLIENT')

        self.perf_library.update_for_failover(mock_client,
                                              self.fake_volumes,
                                              self.fake_aggregates)

        self.assertEqual(mock_client, self.perf_library.zapi_client)
        self.perf_library.update_performance_cache.assert_called_once_with(
            self.fake_volumes, self.fake_aggregates)

    def test_get_aggregates_for_pools(self):

        result = self.perf_library._get_aggregates_for_pools(
            self.fake_volumes, self.fake_aggregates)

        expected_aggregate_names = ['aggr1', 'aggr2', 'aggr3']
        self.assertItemsEqual(expected_aggregate_names, result)

    def test_get_nodes_for_aggregates(self):

        aggregate_names = ['aggr1', 'aggr2', 'aggr3']
        aggregate_nodes = ['node1', 'node2', 'node2']

        mock_get_node_for_aggregate = self.mock_object(
            self.zapi_client, 'get_node_for_aggregate',
            mock.Mock(side_effect=aggregate_nodes))

        result = self.perf_library._get_nodes_for_aggregates(aggregate_names)

        self.assertEqual(2, len(result))
        result_node_names, result_aggr_node_map = result

        expected_node_names = ['node1', 'node2']
        expected_aggr_node_map = dict(zip(aggregate_names, aggregate_nodes))
        self.assertItemsEqual(expected_node_names, result_node_names)
        self.assertEqual(expected_aggr_node_map, result_aggr_node_map)
        mock_get_node_for_aggregate.assert_has_calls([
            mock.call('aggr1'), mock.call('aggr2'), mock.call('aggr3')])

    def test_get_node_utilization_kahuna_overutilized(self):

        mock_get_kahuna_utilization = self.mock_object(
            self.perf_library, '_get_kahuna_utilization',
            mock.Mock(return_value=61.0))
        mock_get_average_cpu_utilization = self.mock_object(
            self.perf_library, '_get_average_cpu_utilization',
            mock.Mock(return_value=25.0))

        result = self.perf_library._get_node_utilization('fake1',
                                                         'fake2',
                                                         'fake_node')

        self.assertAlmostEqual(100.0, result)
        mock_get_kahuna_utilization.assert_called_once_with('fake1', 'fake2')
        self.assertFalse(mock_get_average_cpu_utilization.called)

    @ddt.data({'cpu': -0.01, 'cp_time': 10000, 'poll_time': 0},
              {'cpu': 1.01, 'cp_time': 0, 'poll_time': 1000},
              {'cpu': 0.50, 'cp_time': 0, 'poll_time': 0})
    @ddt.unpack
    def test_get_node_utilization_zero_time(self, cpu, cp_time, poll_time):

        mock_get_kahuna_utilization = self.mock_object(
            self.perf_library, '_get_kahuna_utilization',
            mock.Mock(return_value=59.0))
        mock_get_average_cpu_utilization = self.mock_object(
            self.perf_library, '_get_average_cpu_utilization',
            mock.Mock(return_value=cpu))
        mock_get_total_consistency_point_time = self.mock_object(
            self.perf_library, '_get_total_consistency_point_time',
            mock.Mock(return_value=cp_time))
        mock_get_consistency_point_p2_flush_time = self.mock_object(
            self.perf_library, '_get_consistency_point_p2_flush_time',
            mock.Mock(return_value=cp_time))
        mock_get_total_time = self.mock_object(
            self.perf_library, '_get_total_time',
            mock.Mock(return_value=poll_time))
        mock_get_adjusted_consistency_point_time = self.mock_object(
            self.perf_library, '_get_adjusted_consistency_point_time')

        result = self.perf_library._get_node_utilization('fake1',
                                                         'fake2',
                                                         'fake_node')

        expected = max(min(100.0, 100.0 * cpu), 0)
        self.assertEqual(expected, result)

        mock_get_kahuna_utilization.assert_called_once_with('fake1', 'fake2')
        mock_get_average_cpu_utilization.assert_called_once_with('fake1',
                                                                 'fake2')
        mock_get_total_consistency_point_time.assert_called_once_with('fake1',
                                                                      'fake2')
        mock_get_consistency_point_p2_flush_time.assert_called_once_with(
            'fake1', 'fake2')
        mock_get_total_time.assert_called_once_with('fake1',
                                                    'fake2',
                                                    'total_cp_msecs')
        self.assertFalse(mock_get_adjusted_consistency_point_time.called)

    @ddt.data({'cpu': 0.75, 'adjusted_cp_time': 8000, 'expected': 80},
              {'cpu': 0.80, 'adjusted_cp_time': 7500, 'expected': 80},
              {'cpu': 0.50, 'adjusted_cp_time': 11000, 'expected': 100})
    @ddt.unpack
    def test_get_node_utilization(self, cpu, adjusted_cp_time, expected):

        mock_get_kahuna_utilization = self.mock_object(
            self.perf_library, '_get_kahuna_utilization',
            mock.Mock(return_value=59.0))
        mock_get_average_cpu_utilization = self.mock_object(
            self.perf_library, '_get_average_cpu_utilization',
            mock.Mock(return_value=cpu))
        mock_get_total_consistency_point_time = self.mock_object(
            self.perf_library, '_get_total_consistency_point_time',
            mock.Mock(return_value=90.0))
        mock_get_consistency_point_p2_flush_time = self.mock_object(
            self.perf_library, '_get_consistency_point_p2_flush_time',
            mock.Mock(return_value=50.0))
        mock_get_total_time = self.mock_object(
            self.perf_library, '_get_total_time',
            mock.Mock(return_value=10000))
        mock_get_adjusted_consistency_point_time = self.mock_object(
            self.perf_library, '_get_adjusted_consistency_point_time',
            mock.Mock(return_value=adjusted_cp_time))

        result = self.perf_library._get_node_utilization('fake1',
                                                         'fake2',
                                                         'fake_node')

        self.assertEqual(expected, result)

        mock_get_kahuna_utilization.assert_called_once_with('fake1', 'fake2')
        mock_get_average_cpu_utilization.assert_called_once_with('fake1',
                                                                 'fake2')
        mock_get_total_consistency_point_time.assert_called_once_with('fake1',
                                                                      'fake2')
        mock_get_consistency_point_p2_flush_time.assert_called_once_with(
            'fake1', 'fake2')
        mock_get_total_time.assert_called_once_with('fake1',
                                                    'fake2',
                                                    'total_cp_msecs')
        mock_get_adjusted_consistency_point_time.assert_called_once_with(
            90.0, 50.0)

    def test_get_node_utilization_calculation_error(self):

        self.mock_object(self.perf_library,
                         '_get_kahuna_utilization',
                         mock.Mock(return_value=59.0))
        self.mock_object(self.perf_library,
                         '_get_average_cpu_utilization',
                         mock.Mock(return_value=25.0))
        self.mock_object(self.perf_library,
                         '_get_total_consistency_point_time',
                         mock.Mock(return_value=90.0))
        self.mock_object(self.perf_library,
                         '_get_consistency_point_p2_flush_time',
                         mock.Mock(return_value=50.0))
        self.mock_object(self.perf_library,
                         '_get_total_time',
                         mock.Mock(return_value=10000))
        self.mock_object(self.perf_library,
                         '_get_adjusted_consistency_point_time',
                         mock.Mock(side_effect=ZeroDivisionError))

        result = self.perf_library._get_node_utilization('fake1',
                                                         'fake2',
                                                         'fake_node')

        self.assertEqual(performance.DEFAULT_UTILIZATION, result)
        (self.perf_library._get_adjusted_consistency_point_time.
            assert_called_once_with(mock.ANY, mock.ANY))

    def test_get_kahuna_utilization(self):

        mock_get_performance_counter = self.mock_object(
            self.perf_library,
            '_get_performance_counter_average_multi_instance',
            mock.Mock(return_value=[0.2, 0.3]))

        result = self.perf_library._get_kahuna_utilization('fake_t1',
                                                           'fake_t2')

        self.assertAlmostEqual(50.0, result)
        mock_get_performance_counter.assert_called_once_with(
            'fake_t1', 'fake_t2', 'domain_busy:kahuna',
            'processor_elapsed_time')

    def test_get_average_cpu_utilization(self):

        mock_get_performance_counter_average = self.mock_object(
            self.perf_library, '_get_performance_counter_average',
            mock.Mock(return_value=0.45))

        result = self.perf_library._get_average_cpu_utilization('fake_t1',
                                                                'fake_t2')

        self.assertAlmostEqual(0.45, result)
        mock_get_performance_counter_average.assert_called_once_with(
            'fake_t1', 'fake_t2', 'avg_processor_busy', 'cpu_elapsed_time1')

    def test_get_total_consistency_point_time(self):

        mock_get_performance_counter_delta = self.mock_object(
            self.perf_library, '_get_performance_counter_delta',
            mock.Mock(return_value=500))

        result = self.perf_library._get_total_consistency_point_time(
            'fake_t1', 'fake_t2')

        self.assertEqual(500, result)
        mock_get_performance_counter_delta.assert_called_once_with(
            'fake_t1', 'fake_t2', 'total_cp_msecs')

    def test_get_consistency_point_p2_flush_time(self):

        mock_get_performance_counter_delta = self.mock_object(
            self.perf_library, '_get_performance_counter_delta',
            mock.Mock(return_value=500))

        result = self.perf_library._get_consistency_point_p2_flush_time(
            'fake_t1', 'fake_t2')

        self.assertEqual(500, result)
        mock_get_performance_counter_delta.assert_called_once_with(
            'fake_t1', 'fake_t2', 'cp_phase_times:p2_flush')

    def test_get_total_time(self):

        mock_find_performance_counter_timestamp = self.mock_object(
            self.perf_library, '_find_performance_counter_timestamp',
            mock.Mock(side_effect=[100, 105]))

        result = self.perf_library._get_total_time('fake_t1',
                                                   'fake_t2',
                                                   'fake_counter')

        self.assertEqual(5000, result)
        mock_find_performance_counter_timestamp.assert_has_calls([
            mock.call('fake_t1', 'fake_counter'),
            mock.call('fake_t2', 'fake_counter')])

    def test_get_adjusted_consistency_point_time(self):

        result = self.perf_library._get_adjusted_consistency_point_time(
            500, 200)

        self.assertAlmostEqual(360.0, result)

    def test_get_performance_counter_delta(self):

        result = self.perf_library._get_performance_counter_delta(
            fake.COUNTERS_T1, fake.COUNTERS_T2, 'total_cp_msecs')

        self.assertEqual(1482, result)

    def test_get_performance_counter_average(self):

        result = self.perf_library._get_performance_counter_average(
            fake.COUNTERS_T1, fake.COUNTERS_T2, 'domain_busy:kahuna',
            'processor_elapsed_time', 'processor0')

        self.assertAlmostEqual(0.00281954360981, result)

    def test_get_performance_counter_average_multi_instance(self):

        result = (
            self.perf_library._get_performance_counter_average_multi_instance(
                fake.COUNTERS_T1, fake.COUNTERS_T2, 'domain_busy:kahuna',
                'processor_elapsed_time'))

        expected = [0.002819543609809441, 0.0033421611147606135]
        self.assertAlmostEqual(expected, result)

    def test_find_performance_counter_value(self):

        result = self.perf_library._find_performance_counter_value(
            fake.COUNTERS_T1, 'domain_busy:kahuna',
            instance_name='processor0')

        self.assertEqual('2712467226', result)

    def test_find_performance_counter_value_not_found(self):

        self.assertRaises(
            exception.NotFound,
            self.perf_library._find_performance_counter_value,
            fake.COUNTERS_T1, 'invalid', instance_name='processor0')

    def test_find_performance_counter_timestamp(self):

        result = self.perf_library._find_performance_counter_timestamp(
            fake.COUNTERS_T1, 'domain_busy')

        self.assertEqual('1453573777', result)

    def test_find_performance_counter_timestamp_not_found(self):

        self.assertRaises(
            exception.NotFound,
            self.perf_library._find_performance_counter_timestamp,
            fake.COUNTERS_T1, 'invalid', instance_name='processor0')

    def test_expand_performance_array(self):

        counter_info = {
            'labels': ['idle', 'kahuna', 'storage', 'exempt'],
            'name': 'domain_busy',
        }
        self.zapi_client.get_performance_counter_info = mock.Mock(
            return_value=counter_info)

        counter = {
            'node-name': 'cluster1-01',
            'instance-uuid': 'cluster1-01:kernel:processor0',
            'domain_busy': '969142314286,2567571412,2131582146,5383861579',
            'instance-name': 'processor0',
            'timestamp': '1453512244',
        }
        self.perf_library._expand_performance_array('wafl',
                                                    'domain_busy',
                                                    counter)

        modified_counter = {
            'node-name': 'cluster1-01',
            'instance-uuid': 'cluster1-01:kernel:processor0',
            'domain_busy': '969142314286,2567571412,2131582146,5383861579',
            'instance-name': 'processor0',
            'timestamp': '1453512244',
            'domain_busy:idle': '969142314286',
            'domain_busy:kahuna': '2567571412',
            'domain_busy:storage': '2131582146',
            'domain_busy:exempt': '5383861579',
        }
        self.assertEqual(modified_counter, counter)

    def test_get_base_counter_name(self):

        counter_info = {
            'base-counter': 'cpu_elapsed_time',
            'labels': [],
            'name': 'avg_processor_busy',
        }
        self.zapi_client.get_performance_counter_info = mock.Mock(
            return_value=counter_info)

        result = self.perf_library._get_base_counter_name(
            'system:constituent', 'avg_processor_busy')

        self.assertEqual('cpu_elapsed_time', result)

    def test_get_node_utilization_counters(self):

        mock_get_node_utilization_system_counters = self.mock_object(
            self.perf_library, '_get_node_utilization_system_counters',
            mock.Mock(return_value=['A', 'B', 'C']))
        mock_get_node_utilization_wafl_counters = self.mock_object(
            self.perf_library, '_get_node_utilization_wafl_counters',
            mock.Mock(return_value=['D', 'E', 'F']))
        mock_get_node_utilization_processor_counters = self.mock_object(
            self.perf_library, '_get_node_utilization_processor_counters',
            mock.Mock(return_value=['G', 'H', 'I']))

        result = self.perf_library._get_node_utilization_counters(fake.NODE)

        expected = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I']
        self.assertEqual(expected, result)

        mock_get_node_utilization_system_counters.assert_called_once_with(
            fake.NODE)
        mock_get_node_utilization_wafl_counters.assert_called_once_with(
            fake.NODE)
        mock_get_node_utilization_processor_counters.assert_called_once_with(
            fake.NODE)

    def test_get_node_utilization_counters_api_error(self):

        self.mock_object(self.perf_library,
                         '_get_node_utilization_system_counters',
                         mock.Mock(side_effect=netapp_api.NaApiError))

        result = self.perf_library._get_node_utilization_counters(fake.NODE)

        self.assertIsNone(result)

    def test_get_node_utilization_system_counters(self):

        mock_get_performance_instance_uuids = self.mock_object(
            self.zapi_client, 'get_performance_instance_uuids',
            mock.Mock(return_value=fake.SYSTEM_INSTANCE_UUIDS))
        mock_get_performance_counters = self.mock_object(
            self.zapi_client, 'get_performance_counters',
            mock.Mock(return_value=fake.SYSTEM_COUNTERS))

        result = self.perf_library._get_node_utilization_system_counters(
            fake.NODE)

        self.assertEqual(fake.SYSTEM_COUNTERS, result)

        mock_get_performance_instance_uuids.assert_called_once_with(
            'system', fake.NODE)
        mock_get_performance_counters.assert_called_once_with(
            'system', fake.SYSTEM_INSTANCE_UUIDS,
            ['avg_processor_busy', 'cpu_elapsed_time1', 'cpu_elapsed_time'])

    def test_get_node_utilization_wafl_counters(self):

        mock_get_performance_instance_uuids = self.mock_object(
            self.zapi_client, 'get_performance_instance_uuids',
            mock.Mock(return_value=fake.WAFL_INSTANCE_UUIDS))
        mock_get_performance_counters = self.mock_object(
            self.zapi_client, 'get_performance_counters',
            mock.Mock(return_value=fake.WAFL_COUNTERS))
        mock_get_performance_counter_info = self.mock_object(
            self.zapi_client, 'get_performance_counter_info',
            mock.Mock(return_value=fake.WAFL_CP_PHASE_TIMES_COUNTER_INFO))

        result = self.perf_library._get_node_utilization_wafl_counters(
            fake.NODE)

        self.assertEqual(fake.EXPANDED_WAFL_COUNTERS, result)

        mock_get_performance_instance_uuids.assert_called_once_with(
            'wafl', fake.NODE)
        mock_get_performance_counters.assert_called_once_with(
            'wafl', fake.WAFL_INSTANCE_UUIDS,
            ['total_cp_msecs', 'cp_phase_times'])
        mock_get_performance_counter_info.assert_called_once_with(
            'wafl', 'cp_phase_times')

    def test_get_node_utilization_processor_counters(self):

        mock_get_performance_instance_uuids = self.mock_object(
            self.zapi_client, 'get_performance_instance_uuids',
            mock.Mock(return_value=fake.PROCESSOR_INSTANCE_UUIDS))
        mock_get_performance_counters = self.mock_object(
            self.zapi_client, 'get_performance_counters',
            mock.Mock(return_value=fake.PROCESSOR_COUNTERS))
        self.mock_object(
            self.zapi_client, 'get_performance_counter_info',
            mock.Mock(return_value=fake.PROCESSOR_DOMAIN_BUSY_COUNTER_INFO))

        result = self.perf_library._get_node_utilization_processor_counters(
            fake.NODE)

        self.assertEqual(fake.EXPANDED_PROCESSOR_COUNTERS, result)

        mock_get_performance_instance_uuids.assert_called_once_with(
            'processor', fake.NODE)
        mock_get_performance_counters.assert_called_once_with(
            'processor', fake.PROCESSOR_INSTANCE_UUIDS,
            ['domain_busy', 'processor_elapsed_time'])
