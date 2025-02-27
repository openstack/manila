# Copyright (c) 2011 OpenStack, LLC
# Copyright (c) 2015 Rushil Chugh
# Copyright (c) 2015 Clinton Knight
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
Tests For HostManager
"""

import copy
from unittest import mock

import ddt
from oslo_config import cfg
from oslo_utils import timeutils

from manila import context
from manila import db
from manila import exception
from manila.scheduler.filters import base_host
from manila.scheduler import host_manager
from manila.scheduler import utils as scheduler_utils
from manila import test
from manila.tests.scheduler import fakes
from manila import utils


CONF = cfg.CONF


class FakeFilterClass1(base_host.BaseHostFilter):
    def host_passes(self, host_state, filter_properties):
        pass


class FakeFilterClass2(base_host.BaseHostFilter):
    def host_passes(self, host_state, filter_properties):
        pass


@ddt.ddt
class HostManagerTestCase(test.TestCase):
    """Test case for HostManager class."""

    def setUp(self):
        super(HostManagerTestCase, self).setUp()
        self.host_manager = host_manager.HostManager()
        self.fake_hosts = [host_manager.HostState('fake_host%s' % x)
                           for x in range(1, 5)]

    def test_choose_host_filters_not_found(self):
        self.flags(scheduler_default_filters='FakeFilterClass3')
        self.host_manager.filter_classes = [FakeFilterClass1,
                                            FakeFilterClass2]
        self.assertRaises(exception.SchedulerHostFilterNotFound,
                          self.host_manager._choose_host_filters, None)

    def test_choose_host_filters(self):
        self.flags(scheduler_default_filters=['FakeFilterClass2'])
        self.host_manager.filter_classes = [FakeFilterClass1,
                                            FakeFilterClass2]

        # Test 'share' returns 1 correct function
        filter_classes = self.host_manager._choose_host_filters(None)
        self.assertEqual(1, len(filter_classes))
        self.assertEqual('FakeFilterClass2', filter_classes[0].__name__)

    def _verify_result(self, info, result):
        for x in info['got_fprops']:
            self.assertEqual(info['expected_fprops'], x)
        self.assertEqual(set(info['expected_objs']), set(info['got_objs']))
        self.assertEqual(set(info['got_objs']), set(result))

    def test_get_filtered_hosts(self):
        fake_properties = {'moo': 1, 'cow': 2}
        info = {
            'expected_objs': self.fake_hosts,
            'expected_fprops': fake_properties,
        }
        with mock.patch.object(self.host_manager, '_choose_host_filters',
                               mock.Mock(return_value=[FakeFilterClass1])):
            info['got_objs'] = []
            info['got_fprops'] = []

            def fake_filter_one(_self, obj, filter_props):
                info['got_objs'].append(obj)
                info['got_fprops'].append(filter_props)
                return True

            self.mock_object(FakeFilterClass1, '_filter_one', fake_filter_one)
            result, last_filter = self.host_manager.get_filtered_hosts(
                self.fake_hosts, fake_properties)
            self._verify_result(info, result)
            self.host_manager._choose_host_filters.assert_called_once_with(
                mock.ANY)

    def test_update_service_capabilities_for_shares(self):
        service_states = self.host_manager.service_states
        self.assertDictEqual(service_states, {})
        host1_share_capabs = dict(free_capacity_gb=4321, timestamp=1)
        host2_share_capabs = dict(free_capacity_gb=5432, timestamp=1)
        host3_share_capabs = dict(free_capacity_gb=6543, timestamp=1)
        service_name = 'share'
        self.host_manager.update_service_capabilities(
            service_name, 'host1', host1_share_capabs, 31337)

        self.host_manager.update_service_capabilities(
            service_name, 'host2', host2_share_capabs, 31338)

        self.host_manager.update_service_capabilities(
            service_name, 'host3', host3_share_capabs, 31339)

        # Make sure dictionary isn't re-assigned
        self.assertEqual(service_states, self.host_manager.service_states)
        # Make sure original dictionary wasn't copied
        self.assertEqual(1, host1_share_capabs['timestamp'])

        host1_share_capabs['timestamp'] = 31337
        host2_share_capabs['timestamp'] = 31338
        host3_share_capabs['timestamp'] = 31339

        expected = {
            'host1': host1_share_capabs,
            'host2': host2_share_capabs,
            'host3': host3_share_capabs,
        }
        self.assertDictEqual(service_states, expected)

    def test_get_all_host_states_share(self):
        fake_context = context.RequestContext('user', 'project')
        topic = CONF.share_topic
        tmp_pools = copy.deepcopy(fakes.SHARE_SERVICES_WITH_POOLS)
        tmp_enable_pools = tmp_pools[:-2]
        self.mock_object(
            db, 'service_get_all_by_topic',
            mock.Mock(return_value=tmp_enable_pools))
        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))

        with mock.patch.dict(self.host_manager.service_states,
                             fakes.SHARE_SERVICE_STATES_WITH_POOLS):
            # Get service
            self.host_manager.get_all_host_states_share(fake_context)

            # Disabled one service
            tmp_enable_pools.pop()
            self.mock_object(
                db, 'service_get_all_by_topic',
                mock.Mock(return_value=tmp_enable_pools))

            # Get service again
            self.host_manager.get_all_host_states_share(fake_context)
            host_state_map = self.host_manager.host_state_map

            self.assertEqual(3, len(host_state_map))
            # Check that service is up
            for i in range(3):
                share_node = fakes.SHARE_SERVICES_WITH_POOLS[i]
                host = share_node['host']
                self.assertEqual(share_node, host_state_map[host].service)
            db.service_get_all_by_topic.assert_called_once_with(
                fake_context, topic, consider_disabled=False)

    def test_get_pools_no_pools(self):
        fake_context = context.RequestContext('user', 'project')
        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(
            db, 'service_get_all_by_topic',
            mock.Mock(return_value=fakes.SHARE_SERVICES_NO_POOLS))
        host_manager.LOG.warning = mock.Mock()

        with mock.patch.dict(self.host_manager.service_states,
                             fakes.SERVICE_STATES_NO_POOLS):

            res = self.host_manager.get_pools(context=fake_context)

            expected = [
                {
                    'name': 'host1#AAA',
                    'host': 'host1',
                    'backend': None,
                    'pool': 'AAA',
                    'capabilities': {
                        'timestamp': None,
                        'share_backend_name': 'AAA',
                        'free_capacity_gb': 200,
                        'driver_version': None,
                        'total_capacity_gb': 512,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'provisioned_capacity_gb': 312,
                        'max_over_subscription_ratio': 1.0,
                        'thin_provisioning': False,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': False,
                        'create_share_from_snapshot_support': False,
                        'revert_to_snapshot_support': True,
                        'mount_snapshot_support': True,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                }, {
                    'name': 'host2@back1#BBB',
                    'host': 'host2',
                    'backend': 'back1',
                    'pool': 'BBB',
                    'capabilities': {
                        'timestamp': None,
                        'share_backend_name': 'BBB',
                        'free_capacity_gb': 100,
                        'driver_version': None,
                        'total_capacity_gb': 256,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'provisioned_capacity_gb': 400,
                        'max_over_subscription_ratio': 2.0,
                        'thin_provisioning': True,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': True,
                        'create_share_from_snapshot_support': True,
                        'revert_to_snapshot_support': False,
                        'mount_snapshot_support': False,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                }, {
                    'name': 'host2@back2#CCC',
                    'host': 'host2',
                    'backend': 'back2',
                    'pool': 'CCC',
                    'capabilities': {
                        'timestamp': None,
                        'share_backend_name': 'CCC',
                        'free_capacity_gb': 700,
                        'driver_version': None,
                        'total_capacity_gb': 10000,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'provisioned_capacity_gb': 50000,
                        'max_over_subscription_ratio': 20.0,
                        'thin_provisioning': True,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': True,
                        'create_share_from_snapshot_support': True,
                        'revert_to_snapshot_support': False,
                        'mount_snapshot_support': False,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                },
            ]
            self.assertIsInstance(res, list)
            self.assertEqual(len(expected), len(res))
            for pool in expected:
                self.assertIn(pool, res)

    def test_get_pools(self):
        fake_context = context.RequestContext('user', 'project')
        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(
            db, 'service_get_all_by_topic',
            mock.Mock(return_value=fakes.SHARE_SERVICES_WITH_POOLS))
        host_manager.LOG.warning = mock.Mock()

        with mock.patch.dict(self.host_manager.service_states,
                             fakes.SHARE_SERVICE_STATES_WITH_POOLS):

            res = self.host_manager.get_pools(fake_context)

            expected = [
                {
                    'name': 'host1@AAA#pool1',
                    'host': 'host1',
                    'backend': 'AAA',
                    'pool': 'pool1',
                    'capabilities': {
                        'pool_name': 'pool1',
                        'timestamp': None,
                        'share_backend_name': 'AAA',
                        'free_capacity_gb': 41,
                        'driver_version': None,
                        'total_capacity_gb': 51,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'provisioned_capacity_gb': 10,
                        'max_over_subscription_ratio': 1.0,
                        'thin_provisioning': False,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': True,
                        'create_share_from_snapshot_support': True,
                        'revert_to_snapshot_support': True,
                        'mount_snapshot_support': False,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                }, {
                    'name': 'host2@BBB#pool2',
                    'host': 'host2',
                    'backend': 'BBB',
                    'pool': 'pool2',
                    'capabilities': {
                        'pool_name': 'pool2',
                        'timestamp': None,
                        'share_backend_name': 'BBB',
                        'free_capacity_gb': 42,
                        'driver_version': None,
                        'total_capacity_gb': 52,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'provisioned_capacity_gb': 60,
                        'max_over_subscription_ratio': 2.0,
                        'thin_provisioning': True,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': True,
                        'create_share_from_snapshot_support': True,
                        'revert_to_snapshot_support': False,
                        'mount_snapshot_support': False,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                }, {
                    'name': 'host3@CCC#pool3',
                    'host': 'host3',
                    'backend': 'CCC',
                    'pool': 'pool3',
                    'capabilities': {
                        'pool_name': 'pool3',
                        'timestamp': None,
                        'share_backend_name': 'CCC',
                        'free_capacity_gb': 43,
                        'driver_version': None,
                        'total_capacity_gb': 53,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'provisioned_capacity_gb': 100,
                        'max_over_subscription_ratio': 20.0,
                        'thin_provisioning': True,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': True,
                        'create_share_from_snapshot_support': True,
                        'revert_to_snapshot_support': False,
                        'mount_snapshot_support': False,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                }, {
                    'name': 'host4@DDD#pool4a',
                    'host': 'host4',
                    'backend': 'DDD',
                    'pool': 'pool4a',
                    'capabilities': {
                        'pool_name': 'pool4a',
                        'timestamp': None,
                        'share_backend_name': 'DDD',
                        'free_capacity_gb': 441,
                        'driver_version': None,
                        'total_capacity_gb': 541,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'provisioned_capacity_gb': 800,
                        'max_over_subscription_ratio': 2.0,
                        'thin_provisioning': True,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': True,
                        'create_share_from_snapshot_support': True,
                        'revert_to_snapshot_support': False,
                        'mount_snapshot_support': False,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                }, {
                    'name': 'host4@DDD#pool4b',
                    'host': 'host4',
                    'backend': 'DDD',
                    'pool': 'pool4b',
                    'capabilities': {
                        'pool_name': 'pool4b',
                        'timestamp': None,
                        'share_backend_name': 'DDD',
                        'free_capacity_gb': 442,
                        'driver_version': None,
                        'total_capacity_gb': 542,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'provisioned_capacity_gb': 2000,
                        'max_over_subscription_ratio': 10.0,
                        'thin_provisioning': True,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': True,
                        'create_share_from_snapshot_support': True,
                        'revert_to_snapshot_support': False,
                        'mount_snapshot_support': False,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                },
            ]
            self.assertIsInstance(res, list)
            self.assertIsInstance(self.host_manager.host_state_map, dict)
            self.assertEqual(len(expected), len(res))
            for pool in expected:
                self.assertIn(pool, res)

    def test_get_pools_host_down(self):
        fake_context = context.RequestContext('user', 'project')
        mock_service_is_up = self.mock_object(utils, 'service_is_up')
        self.mock_object(
            db, 'service_get_all_by_topic',
            mock.Mock(return_value=fakes.SHARE_SERVICES_NO_POOLS))
        host_manager.LOG.warning = mock.Mock()

        with mock.patch.dict(self.host_manager.service_states,
                             fakes.SERVICE_STATES_NO_POOLS):

            # Initialize host data with all services present
            mock_service_is_up.side_effect = [True, True, True]

            # Call once to update the host state map
            self.host_manager.get_pools(fake_context)

            self.assertEqual(len(fakes.SHARE_SERVICES_NO_POOLS),
                             len(self.host_manager.host_state_map))

            # Then mock one host as down
            mock_service_is_up.side_effect = [True, True, False]

            res = self.host_manager.get_pools(fake_context)

            expected = [
                {
                    'name': 'host1#AAA',
                    'host': 'host1',
                    'backend': None,
                    'pool': 'AAA',
                    'capabilities': {
                        'timestamp': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': False,
                        'create_share_from_snapshot_support': False,
                        'revert_to_snapshot_support': True,
                        'mount_snapshot_support': True,
                        'share_backend_name': 'AAA',
                        'free_capacity_gb': 200,
                        'driver_version': None,
                        'total_capacity_gb': 512,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'provisioned_capacity_gb': 312,
                        'max_over_subscription_ratio': 1.0,
                        'thin_provisioning': False,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                }, {
                    'name': 'host2@back1#BBB',
                    'host': 'host2',
                    'backend': 'back1',
                    'pool': 'BBB',
                    'capabilities': {
                        'timestamp': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': True,
                        'create_share_from_snapshot_support': True,
                        'revert_to_snapshot_support': False,
                        'mount_snapshot_support': False,
                        'share_backend_name': 'BBB',
                        'free_capacity_gb': 100,
                        'driver_version': None,
                        'total_capacity_gb': 256,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'provisioned_capacity_gb': 400,
                        'max_over_subscription_ratio': 2.0,
                        'thin_provisioning': True,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False
                    },
                },
            ]
            self.assertIsInstance(res, list)
            self.assertIsInstance(self.host_manager.host_state_map, dict)
            self.assertEqual(len(expected), len(res))
            self.assertEqual(len(expected),
                             len(self.host_manager.host_state_map))
            for pool in expected:
                self.assertIn(pool, res)

    def test_get_pools_with_filters(self):
        fake_context = context.RequestContext('user', 'project')
        self.mock_object(utils, 'service_is_up', mock.Mock(return_value=True))
        self.mock_object(
            db, 'service_get_all_by_topic',
            mock.Mock(return_value=fakes.SHARE_SERVICES_WITH_POOLS))
        host_manager.LOG.warning = mock.Mock()

        with mock.patch.dict(self.host_manager.service_states,
                             fakes.SHARE_SERVICE_STATES_WITH_POOLS):

            res = self.host_manager.get_pools(
                context=fake_context,
                filters={'host': 'host2', 'pool': 'pool*',
                         'capabilities': {'dedupe': 'False'}})

            expected = [
                {
                    'name': 'host2@BBB#pool2',
                    'host': 'host2',
                    'backend': 'BBB',
                    'pool': 'pool2',
                    'capabilities': {
                        'pool_name': 'pool2',
                        'timestamp': None,
                        'driver_handles_share_servers': False,
                        'snapshot_support': True,
                        'create_share_from_snapshot_support': True,
                        'revert_to_snapshot_support': False,
                        'mount_snapshot_support': False,
                        'share_backend_name': 'BBB',
                        'free_capacity_gb': 42,
                        'driver_version': None,
                        'total_capacity_gb': 52,
                        'reserved_percentage': 0,
                        'reserved_snapshot_percentage': 0,
                        'reserved_share_extend_percentage': 0,
                        'provisioned_capacity_gb': 60,
                        'max_over_subscription_ratio': 2.0,
                        'thin_provisioning': True,
                        'vendor_name': None,
                        'storage_protocol': None,
                        'dedupe': False,
                        'compression': False,
                        'replication_type': None,
                        'replication_domain': None,
                        'sg_consistent_snapshot_support': None,
                        'security_service_update_support': False,
                        'network_allocation_update_support': False,
                        'share_server_multiple_subnet_support': False,
                        'mount_point_name_support': False,
                        'share_replicas_migration_support': False,
                    },
                },
            ]
            self.assertIsInstance(res, list)
            self.assertEqual(len(expected), len(res))
            for pool in expected:
                self.assertIn(pool, res)

    @ddt.data(
        None,
        {},
        {'key1': 'value1'},
        {'capabilities': {'dedupe': 'False'}},
        {'capabilities': {'dedupe': '<is> False'}},
        {'key1': 'value1', 'key2': 'value*'},
        {'key1': '.*', 'key2': '.*'},
    )
    def test_passes_filters_true(self, filter):

        data = {
            'key1': 'value1',
            'key2': 'value2',
            'key3': 'value3',
            'capabilities': {'dedupe': False},
        }
        self.assertTrue(self.host_manager._passes_filters(data, filter))

    @ddt.data(
        {'key1': 'value$'},
        {'key4': 'value'},
        {'capabilities': {'dedupe': 'True'}},
        {'capabilities': {'dedupe': '<is> True'}},
        {'key1': 'value1.+', 'key2': 'value*'},
    )
    def test_passes_filters_false(self, filter):

        data = {
            'key1': 'value1',
            'key2': 'value2',
            'key3': 'value3',
            'capabilities': {'dedupe': False},
        }
        self.assertFalse(self.host_manager._passes_filters(data, filter))


class HostStateTestCase(test.TestCase):
    """Test case for HostState class."""

    def test_update_from_share_capability_nopool(self):
        fake_context = context.RequestContext('user', 'project', is_admin=True)
        share_capability = {'total_capacity_gb': 0,
                            'free_capacity_gb': 100,
                            'reserved_percentage': 0,
                            'reserved_snapshot_percentage': 0,
                            'reserved_share_extend_percentage': 0,
                            'timestamp': None,
                            'ipv4_support': True,
                            'ipv6_support': False}
        fake_host = host_manager.HostState('host1', share_capability)
        self.assertIsNone(fake_host.free_capacity_gb)

        fake_host.update_from_share_capability(share_capability,
                                               context=fake_context)
        # Backend level stats remain uninitialized
        self.assertEqual(0, fake_host.total_capacity_gb)
        self.assertIsNone(fake_host.free_capacity_gb)
        self.assertTrue(fake_host.ipv4_support)
        self.assertFalse(fake_host.ipv6_support)
        # Pool stats has been updated
        self.assertEqual(0, fake_host.pools['_pool0'].total_capacity_gb)
        self.assertEqual(100, fake_host.pools['_pool0'].free_capacity_gb)
        self.assertTrue(fake_host.pools['_pool0'].ipv4_support)
        self.assertFalse(fake_host.pools['_pool0'].ipv6_support)

        # Test update for existing host state
        share_capability.update(dict(total_capacity_gb=1000))
        fake_host.update_from_share_capability(share_capability,
                                               context=fake_context)
        self.assertEqual(1000, fake_host.pools['_pool0'].total_capacity_gb)

        # Test update for existing host state with different backend name
        share_capability.update(dict(share_backend_name='magic'))
        fake_host.update_from_share_capability(share_capability,
                                               context=fake_context)
        self.assertEqual(1000, fake_host.pools['magic'].total_capacity_gb)
        self.assertEqual(100, fake_host.pools['magic'].free_capacity_gb)
        # 'pool0' becomes nonactive pool, and is deleted
        self.assertRaises(KeyError, lambda: fake_host.pools['pool0'])

    def test_update_from_share_capability_with_pools(self):
        fake_context = context.RequestContext('user', 'project', is_admin=True)
        fake_host = host_manager.HostState('host1#pool1')
        self.assertIsNone(fake_host.free_capacity_gb)
        capability = {
            'share_backend_name': 'Backend1',
            'vendor_name': 'OpenStack',
            'driver_version': '1.1',
            'storage_protocol': 'NFS_CIFS',
            'ipv4_support': True,
            'ipv6_support': False,
            'pools': [
                {'pool_name': 'pool1',
                 'total_capacity_gb': 500,
                 'free_capacity_gb': 230,
                 'allocated_capacity_gb': 270,
                 'qos': 'False',
                 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'dying_disks': 100,
                 'super_hero_1': 'spider-man',
                 'super_hero_2': 'flash',
                 'super_hero_3': 'neoncat',
                 },
                {'pool_name': 'pool2',
                 'total_capacity_gb': 1024,
                 'free_capacity_gb': 1024,
                 'allocated_capacity_gb': 0,
                 'qos': 'False',
                 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'dying_disks': 200,
                 'super_hero_1': 'superman',
                 'super_hero_2': 'Hulk',
                 }
            ],
            'timestamp': None,
        }

        fake_host.update_from_share_capability(capability,
                                               context=fake_context)

        self.assertEqual('Backend1', fake_host.share_backend_name)
        self.assertEqual('NFS_CIFS', fake_host.storage_protocol)
        self.assertEqual('OpenStack', fake_host.vendor_name)
        self.assertEqual('1.1', fake_host.driver_version)
        self.assertTrue(fake_host.ipv4_support)
        self.assertFalse(fake_host.ipv6_support)

        # Backend level stats remain uninitialized
        self.assertEqual(0, fake_host.total_capacity_gb)
        self.assertIsNone(fake_host.free_capacity_gb)
        # Pool stats has been updated
        self.assertEqual(2, len(fake_host.pools))

        self.assertEqual(500, fake_host.pools['pool1'].total_capacity_gb)
        self.assertEqual(230, fake_host.pools['pool1'].free_capacity_gb)
        self.assertTrue(fake_host.pools['pool1'].ipv4_support)
        self.assertFalse(fake_host.pools['pool1'].ipv6_support)
        self.assertEqual(1024, fake_host.pools['pool2'].total_capacity_gb)
        self.assertEqual(1024, fake_host.pools['pool2'].free_capacity_gb)
        self.assertTrue(fake_host.pools['pool2'].ipv4_support)
        self.assertFalse(fake_host.pools['pool2'].ipv6_support)

        capability = {
            'share_backend_name': 'Backend1',
            'vendor_name': 'OpenStack',
            'driver_version': '1.0',
            'storage_protocol': 'NFS_CIFS',
            'pools': [
                {'pool_name': 'pool3',
                 'total_capacity_gb': 10000,
                 'free_capacity_gb': 10000,
                 'allocated_capacity_gb': 0,
                 'qos': 'False',
                 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 },
            ],
            'timestamp': None,
        }

        # test update HostState Record
        fake_host.update_from_share_capability(capability,
                                               context=fake_context)

        self.assertEqual('1.0', fake_host.driver_version)

        # Non-active pool stats has been removed
        self.assertEqual(1, len(fake_host.pools))

        self.assertRaises(KeyError, lambda: fake_host.pools['pool1'])
        self.assertRaises(KeyError, lambda: fake_host.pools['pool2'])

        self.assertEqual(10000, fake_host.pools['pool3'].total_capacity_gb)
        self.assertEqual(10000, fake_host.pools['pool3'].free_capacity_gb)

    def test_update_from_share_unknown_capability(self):
        share_capability = {
            'total_capacity_gb': 'unknown',
            'free_capacity_gb': 'unknown',
            'allocated_capacity_gb': 1,
            'reserved_percentage': 0,
            'reserved_snapshot_percentage': 0,
            'reserved_share_extend_percentage': 0,
            'timestamp': None
        }
        fake_context = context.RequestContext('user', 'project', is_admin=True)
        fake_host = host_manager.HostState('host1#_pool0')
        self.assertIsNone(fake_host.free_capacity_gb)
        fake_host.update_from_share_capability(share_capability,
                                               context=fake_context)
        # Backend level stats remain uninitialized
        self.assertEqual(fake_host.total_capacity_gb, 0)
        self.assertIsNone(fake_host.free_capacity_gb)
        # Pool stats has been updated
        self.assertEqual(fake_host.pools['_pool0'].total_capacity_gb,
                         'unknown')
        self.assertEqual(fake_host.pools['_pool0'].free_capacity_gb,
                         'unknown')

    def test_consume_from_share_capability(self):
        fake_context = context.RequestContext('user', 'project', is_admin=True)
        share_size = 10
        free_capacity = 100
        provisioned_capacity_gb = 50
        fake_share = {'id': 'foo', 'size': share_size}
        share_capability = {
            'total_capacity_gb': free_capacity * 2,
            'free_capacity_gb': free_capacity,
            'provisioned_capacity_gb': provisioned_capacity_gb,
            'allocated_capacity_gb': provisioned_capacity_gb,
            'reserved_percentage': 0,
            'reserved_snapshot_percentage': 0,
            'reserved_share_extend_percentage': 0,
            'timestamp': None
        }
        fake_host = host_manager.PoolState('host1', share_capability, '_pool0')

        fake_host.update_from_share_capability(share_capability,
                                               context=fake_context)
        fake_host.consume_from_share(fake_share)
        self.assertEqual(fake_host.free_capacity_gb,
                         free_capacity - share_size)
        self.assertEqual(fake_host.provisioned_capacity_gb,
                         provisioned_capacity_gb + share_size)
        self.assertEqual(fake_host.allocated_capacity_gb,
                         provisioned_capacity_gb + share_size)

    def test_consume_from_share_unknown_capability(self):
        share_capability = {
            'total_capacity_gb': 'unknown',
            'free_capacity_gb': 'unknown',
            'provisioned_capacity_gb': None,
            'allocated_capacity_gb': 0,
            'reserved_percentage': 0,
            'reserved_snapshot_percentage': 0,
            'reserved_share_extend_percentage': 0,
            'timestamp': None
        }
        fake_context = context.RequestContext('user', 'project', is_admin=True)
        fake_host = host_manager.PoolState('host1', share_capability, '_pool0')
        share_size = 1000
        fake_share = {'id': 'foo', 'size': share_size}

        fake_host.update_from_share_capability(share_capability,
                                               context=fake_context)
        fake_host.consume_from_share(fake_share)
        self.assertEqual(fake_host.total_capacity_gb, 'unknown')
        self.assertEqual(fake_host.free_capacity_gb, 'unknown')
        self.assertIsNone(fake_host.provisioned_capacity_gb)
        self.assertEqual(fake_host.allocated_capacity_gb, share_size)

    def test_consume_from_share_invalid_capacity(self):
        fake_host = host_manager.PoolState('host1', {}, '_pool0')
        fake_host.free_capacity_gb = 'invalid_foo_string'
        fake_host.provisioned_capacity_gb = None
        fake_host.allocated_capacity_gb = 0
        fake_share = {'id': 'fake', 'size': 10}

        self.assertRaises(exception.InvalidCapacity,
                          fake_host.consume_from_share, fake_share)

    def test_repr(self):

        capability = {
            'share_backend_name': 'Backend1',
            'vendor_name': 'OpenStack',
            'driver_version': '1.0',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 20000,
            'free_capacity_gb': 15000,
            'allocated_capacity_gb': 5000,
            'timestamp': None,
            'reserved_percentage': 0,
            'reserved_snapshot_percentage': 0,
            'reserved_share_extend_percentage': 0,
        }
        fake_context = context.RequestContext('user', 'project', is_admin=True)
        fake_host = host_manager.HostState('host1')
        fake_host.update_from_share_capability(capability,
                                               context=fake_context)

        result = fake_host.__repr__()
        expected = ("host: 'host1', free_capacity_gb: None, "
                    "pools: {'Backend1': host: 'host1#Backend1', "
                    "free_capacity_gb: 15000, pools: None}")
        self.assertEqual(expected, result)


@ddt.ddt
class PoolStateTestCase(test.TestCase):
    """Test case for HostState class."""

    @ddt.data(
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'reserved_percentage': 0, 'timestamp': None,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'thin_provisioning': True,
                 'cap1': 'val1', 'cap2': 'val2'},
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 4,
                        'updated_at': timeutils.utcnow()
                    },
                    {
                        'id': 2, 'host': 'host1',
                        'status': 'available',
                        'share_id': 12, 'size': None,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'reserved_percentage': 0, 'timestamp': None,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'thin_provisioning': False, 'cap1': 'val1', 'cap2': 'val2'},
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 1,
                        'updated_at': timeutils.utcnow()
                    },
                    {
                        'id': 2, 'host': 'host1',
                        'status': 'available',
                        'share_id': 12, 'size': None,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'reserved_percentage': 0, 'timestamp': None,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'thin_provisioning': [False], 'cap1': 'val1', 'cap2': 'val2'},
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 1,
                        'updated_at': timeutils.utcnow()
                    },
                    {
                        'id': 2, 'host': 'host1',
                        'status': 'available',
                        'share_id': 12, 'size': None,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'reserved_percentage': 0, 'timestamp': None,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'thin_provisioning': [True, False], 'cap1': 'val1',
                 'cap2': 'val2'},
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 4,
                        'updated_at': timeutils.utcnow()
                    },
                    {
                        'id': 2, 'host': 'host1',
                        'status': 'available',
                        'share_id': 12, 'size': None,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'reserved_percentage': 0, 'timestamp': None,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'cap1': 'val1', 'cap2': 'val2', 'ipv4_support': True,
                 'ipv6_support': False},
            'instances': []
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'reserved_percentage': 0, 'timestamp': None,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'thin_provisioning': True, 'cap1': 'val1', 'cap2': 'val2',
                 'ipv4_support': True, 'ipv6_support': False},
            'instances': []
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'reserved_percentage': 0, 'timestamp': None,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'thin_provisioning': [False], 'cap1': 'val1', 'cap2': 'val2',
                 'ipv4_support': True, 'ipv6_support': False},
            'instances': []
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'reserved_percentage': 0, 'timestamp': None,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'thin_provisioning': [True, False], 'cap1': 'val1',
                 'cap2': 'val2', 'ipv4_support': True, 'ipv6_support': False},
            'instances': []
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'allocated_capacity_gb': 256, 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'timestamp': None, 'cap1': 'val1', 'cap2': 'val2',
                 'ipv4_support': False, 'ipv6_support': True
                 },
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 4,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'allocated_capacity_gb': 256, 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'timestamp': None, 'cap1': 'val1', 'cap2': 'val2',
                 'ipv4_support': True, 'ipv6_support': True},
            'instances': []
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'provisioned_capacity_gb': 256, 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'timestamp': None, 'cap1': 'val1', 'cap2': 'val2',
                 'ipv4_support': False, 'ipv6_support': False
                 },
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 1,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'allocated_capacity_gb': 256, 'provisioned_capacity_gb': 1,
                 'thin_provisioning': True, 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'timestamp': None, 'cap1': 'val1', 'cap2': 'val2'},
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 1,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'allocated_capacity_gb': 256, 'provisioned_capacity_gb': 1,
                 'thin_provisioning': [False], 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'timestamp': None, 'cap1': 'val1', 'cap2': 'val2'},
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 1,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'allocated_capacity_gb': 256, 'provisioned_capacity_gb': 1,
                 'thin_provisioning': [True, False], 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'timestamp': None, 'cap1': 'val1', 'cap2': 'val2'},
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 1,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'allocated_capacity_gb': 256, 'provisioned_capacity_gb': 256,
                 'thin_provisioning': False, 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'timestamp': None, 'cap1': 'val1', 'cap2': 'val2'},
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 1,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
        {
            'share_capability':
                {'total_capacity_gb': 1024, 'free_capacity_gb': 512,
                 'allocated_capacity_gb': 256, 'provisioned_capacity_gb': 256,
                 'thin_provisioning': [False], 'reserved_percentage': 0,
                 'reserved_snapshot_percentage': 0,
                 'reserved_share_extend_percentage': 0,
                 'timestamp': None, 'cap1': 'val1', 'cap2': 'val2'},
            'instances':
                [
                    {
                        'id': 1, 'host': 'host1',
                        'status': 'available',
                        'share_id': 11, 'size': 1,
                        'updated_at': timeutils.utcnow()
                    },
                ]
        },
    )
    @ddt.unpack
    def test_update_from_share_capability(self, share_capability, instances):
        fake_context = context.RequestContext('user', 'project', is_admin=True)
        self.mock_object(
            db, 'share_instance_get_all_by_host',
            mock.Mock(return_value=instances))
        fake_pool = host_manager.PoolState('host1', None, 'pool0')
        self.assertIsNone(fake_pool.free_capacity_gb)

        fake_pool.update_from_share_capability(share_capability,
                                               context=fake_context)

        self.assertEqual('host1#pool0', fake_pool.host)
        self.assertEqual('pool0', fake_pool.pool_name)
        self.assertEqual(1024, fake_pool.total_capacity_gb)
        self.assertEqual(512, fake_pool.free_capacity_gb)
        self.assertDictEqual(share_capability, dict(fake_pool.capabilities))

        if 'thin_provisioning' in share_capability:
            thin_provisioned = scheduler_utils.thin_provisioning(
                share_capability['thin_provisioning'])
        else:
            thin_provisioned = False

        if thin_provisioned:
            self.assertEqual(thin_provisioned, fake_pool.thin_provisioning)
            if 'provisioned_capacity_gb' not in share_capability or (
                    share_capability['provisioned_capacity_gb'] is None):
                db.share_instance_get_all_by_host.assert_called_once_with(
                    fake_context, fake_pool.host, with_share_data=True)
                if len(instances) > 0:
                    self.assertEqual(4, fake_pool.provisioned_capacity_gb)
                else:
                    self.assertEqual(0, fake_pool.provisioned_capacity_gb)
            else:
                self.assertFalse(db.share_instance_get_all_by_host.called)
                self.assertEqual(share_capability['provisioned_capacity_gb'],
                                 fake_pool.provisioned_capacity_gb)
        else:
            self.assertFalse(fake_pool.thin_provisioning)
            self.assertFalse(db.share_instance_get_all_by_host.called)
            if 'provisioned_capacity_gb' not in share_capability or (
                    share_capability['provisioned_capacity_gb'] is None):
                self.assertIsNone(fake_pool.provisioned_capacity_gb)
            else:
                self.assertEqual(share_capability['provisioned_capacity_gb'],
                                 fake_pool.provisioned_capacity_gb)

        if 'allocated_capacity_gb' in share_capability:
            self.assertEqual(share_capability['allocated_capacity_gb'],
                             fake_pool.allocated_capacity_gb)
        else:
            self.assertEqual(0, fake_pool.allocated_capacity_gb)

        if 'ipv4_support' in share_capability:
            self.assertEqual(share_capability['ipv4_support'],
                             fake_pool.ipv4_support)
        if 'ipv6_support' in share_capability:
            self.assertEqual(share_capability['ipv6_support'],
                             fake_pool.ipv6_support)
