# Copyright (c) 2011 OpenStack, LLC
# Copyright (c) 2015 Rushil Chugh
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
import mock
from oslo_config import cfg
from oslo_utils import timeutils
from six import moves

from manila import db
from manila import exception
from manila.openstack.common.scheduler import filters
from manila.scheduler import host_manager
from manila import test
from manila.tests.scheduler import fakes


CONF = cfg.CONF


class FakeFilterClass1(filters.BaseHostFilter):
    def host_passes(self, host_state, filter_properties):
        pass


class FakeFilterClass2(filters.BaseHostFilter):
    def host_passes(self, host_state, filter_properties):
        pass


class HostManagerTestCase(test.TestCase):
    """Test case for HostManager class."""

    def setUp(self):
        super(HostManagerTestCase, self).setUp()
        self.host_manager = host_manager.HostManager()
        self.fake_hosts = [host_manager.HostState('fake_host%s' % x)
                           for x in moves.range(1, 5)]

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
        self.assertEqual(set(result), set(info['got_objs']))

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
            result = self.host_manager.get_filtered_hosts(self.fake_hosts,
                                                          fake_properties)
            self._verify_result(info, result)
            self.host_manager._choose_host_filters.assert_called_once_with(
                mock.ANY)

    def test_update_service_capabilities_for_shares(self):
        service_states = self.host_manager.service_states
        self.assertDictMatch(service_states, {})
        host1_share_capabs = dict(free_capacity_gb=4321, timestamp=1)
        host2_share_capabs = dict(free_capacity_gb=5432, timestamp=1)
        host3_share_capabs = dict(free_capacity_gb=6543, timestamp=1)
        service_name = 'share'
        with mock.patch.object(timeutils, 'utcnow',
                               mock.Mock(return_value=31337)):
            self.host_manager.update_service_capabilities(
                service_name, 'host1', host1_share_capabs)
            timeutils.utcnow.assert_called_once_with()
        with mock.patch.object(timeutils, 'utcnow',
                               mock.Mock(return_value=31338)):
            self.host_manager.update_service_capabilities(
                service_name, 'host2', host2_share_capabs)
            timeutils.utcnow.assert_called_once_with()
        with mock.patch.object(timeutils, 'utcnow',
                               mock.Mock(return_value=31339)):
            self.host_manager.update_service_capabilities(
                service_name, 'host3', host3_share_capabs)
            timeutils.utcnow.assert_called_once_with()

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
        self.assertDictMatch(service_states, expected)

    def test_get_all_host_states_share(self):
        context = 'fake_context'
        topic = CONF.share_topic
        ret_services = fakes.SHARE_SERVICES
        with mock.patch.object(db, 'service_get_all_by_topic',
                               mock.Mock(return_value=ret_services)):
            # Disabled service
            self.host_manager.get_all_host_states_share(context)
            host_state_map = self.host_manager.host_state_map

            self.assertEqual(4, len(host_state_map))
            # Check that service is up
            for i in xrange(4):
                share_node = fakes.SHARE_SERVICES[i]
                host = share_node['host']
                self.assertEqual(share_node, host_state_map[host].service)
            db.service_get_all_by_topic.assert_called_once_with(context, topic)

    @mock.patch('manila.db.service_get_all_by_topic')
    @mock.patch('manila.utils.service_is_up')
    def test_get_pools(self, _mock_service_is_up,
                       _mock_service_get_all_by_topic):
        context = 'fake_context'

        services = [
            dict(id=1, host='host1', topic='share', disabled=False,
                 availability_zone='zone1', updated_at=timeutils.utcnow()),
            dict(id=2, host='host2@back1', topic='share', disabled=False,
                 availability_zone='zone1', updated_at=timeutils.utcnow()),
            dict(id=3, host='host2@back2', topic='share', disabled=False,
                 availability_zone='zone2', updated_at=timeutils.utcnow()),
        ]

        mocked_service_states = {
            'host1': dict(share_backend_name='AAA',
                          total_capacity_gb=512, free_capacity_gb=200,
                          timestamp=None, reserved_percentage=0,
                          driver_handles_share_servers=False),
            'host2@back1': dict(share_backend_name='BBB',
                                total_capacity_gb=256, free_capacity_gb=100,
                                timestamp=None, reserved_percentage=0,
                                driver_handles_share_servers=False),
            'host2@back2': dict(share_backend_name='CCC',
                                total_capacity_gb=10000, free_capacity_gb=700,
                                timestamp=None, reserved_percentage=0,
                                driver_handles_share_servers=False),
        }

        _mock_service_get_all_by_topic.return_value = services
        _mock_service_is_up.return_value = True
        _mock_warning = mock.Mock()
        host_manager.LOG.warn = _mock_warning

        with mock.patch.dict(self.host_manager.service_states,
                             mocked_service_states):
            # Call get_all_host_states to populate host_state_map
            self.host_manager.get_all_host_states_share(context)

            res = self.host_manager.get_pools(context)

            # Check if get_pools returns all 3 pools
            self.assertEqual(3, len(res))

            expected = [
                {
                    'name': 'host1#AAA',
                    'capabilities': {
                        'timestamp': None,
                        'driver_handles_share_servers': False,
                        'share_backend_name': 'AAA',
                        'free_capacity_gb': 200,
                        'driver_version': None,
                        'total_capacity_gb': 512,
                        'reserved_percentage': 0,
                        'vendor_name': None,
                        'storage_protocol': None},
                },
                {
                    'name': 'host2@back1#BBB',
                    'capabilities': {
                        'timestamp': None,
                        'driver_handles_share_servers': False,
                        'share_backend_name': 'BBB',
                        'free_capacity_gb': 100,
                        'driver_version': None,
                        'total_capacity_gb': 256,
                        'reserved_percentage': 0,
                        'vendor_name': None,
                        'storage_protocol': None},
                },
                {
                    'name': 'host2@back2#CCC',
                    'capabilities': {
                        'timestamp': None,
                        'driver_handles_share_servers': False,
                        'share_backend_name': 'CCC',
                        'free_capacity_gb': 700,
                        'driver_version': None,
                        'total_capacity_gb': 10000,
                        'reserved_percentage': 0,
                        'vendor_name': None,
                        'storage_protocol': None},
                }
            ]
            self.assertEqual(len(expected), len(res))
            self.assertEqual(sorted(expected), sorted(res))


class HostStateTestCase(test.TestCase):
    """Test case for HostState class."""

    def test_update_from_share_capability_nopool(self):
        share_capability = {'total_capacity_gb': 0,
                            'free_capacity_gb': 100,
                            'reserved_percentage': 0,
                            'timestamp': None}
        fake_host = host_manager.HostState('host1', share_capability)
        self.assertIsNone(fake_host.free_capacity_gb)

        fake_host.update_from_share_capability(share_capability)
        # Backend level stats remain uninitialized
        self.assertEqual(0, fake_host.total_capacity_gb)
        self.assertIsNone(fake_host.free_capacity_gb)
        # Pool stats has been updated
        self.assertEqual(0, fake_host.pools['_pool0'].total_capacity_gb)
        self.assertEqual(100, fake_host.pools['_pool0'].free_capacity_gb)

        # Test update for existing host state
        share_capability.update(dict(total_capacity_gb=1000))
        fake_host.update_from_share_capability(share_capability)
        self.assertEqual(1000, fake_host.pools['_pool0'].total_capacity_gb)

        # Test update for existing host state with different backend name
        share_capability.update(dict(share_backend_name='magic'))
        fake_host.update_from_share_capability(share_capability)
        self.assertEqual(1000, fake_host.pools['magic'].total_capacity_gb)
        self.assertEqual(100, fake_host.pools['magic'].free_capacity_gb)
        # 'pool0' becomes nonactive pool, and is deleted
        self.assertRaises(KeyError, lambda: fake_host.pools['pool0'])

    def test_update_from_share_capability_with_pools(self):
        fake_host = host_manager.HostState('host1#pool1')
        self.assertIsNone(fake_host.free_capacity_gb)
        capability = {
            'share_backend_name': 'Backend1',
            'vendor_name': 'OpenStack',
            'driver_version': '1.1',
            'storage_protocol': 'NFS_CIFS',
            'pools': [
                {'pool_name': 'pool1',
                 'total_capacity_gb': 500,
                 'free_capacity_gb': 230,
                 'allocated_capacity_gb': 270,
                 'QoS_support': 'False',
                 'reserved_percentage': 0,
                 'dying_disks': 100,
                 'super_hero_1': 'spider-man',
                 'super_hero_2': 'flash',
                 'super_hero_3': 'neoncat',
                 },
                {'pool_name': 'pool2',
                 'total_capacity_gb': 1024,
                 'free_capacity_gb': 1024,
                 'allocated_capacity_gb': 0,
                 'QoS_support': 'False',
                 'reserved_percentage': 0,
                 'dying_disks': 200,
                 'super_hero_1': 'superman',
                 'super_hero_2': ' ',
                 'super_hero_2': 'Hulk',
                 }
            ],
            'timestamp': None,
        }

        fake_host.update_from_share_capability(capability)

        self.assertEqual('Backend1', fake_host.share_backend_name)
        self.assertEqual('NFS_CIFS', fake_host.storage_protocol)
        self.assertEqual('OpenStack', fake_host.vendor_name)
        self.assertEqual('1.1', fake_host.driver_version)

        # Backend level stats remain uninitialized
        self.assertEqual(0, fake_host.total_capacity_gb)
        self.assertIsNone(fake_host.free_capacity_gb)
        # Pool stats has been updated
        self.assertEqual(2, len(fake_host.pools))

        self.assertEqual(500, fake_host.pools['pool1'].total_capacity_gb)
        self.assertEqual(230, fake_host.pools['pool1'].free_capacity_gb)
        self.assertEqual(1024, fake_host.pools['pool2'].total_capacity_gb)
        self.assertEqual(1024, fake_host.pools['pool2'].free_capacity_gb)

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
                 'QoS_support': 'False',
                 'reserved_percentage': 0,
                 },
            ],
            'timestamp': None,
        }

        # test update HostState Record
        fake_host.update_from_share_capability(capability)

        self.assertEqual('1.0', fake_host.driver_version)

        # Non-active pool stats has been removed
        self.assertEqual(1, len(fake_host.pools))

        self.assertRaises(KeyError, lambda: fake_host.pools['pool1'])
        self.assertRaises(KeyError, lambda: fake_host.pools['pool2'])

        self.assertEqual(10000, fake_host.pools['pool3'].total_capacity_gb)
        self.assertEqual(10000, fake_host.pools['pool3'].free_capacity_gb)

    def test_update_from_share_infinite_capability(self):
        share_capability = {'total_capacity_gb': 'infinite',
                            'free_capacity_gb': 'infinite',
                            'reserved_percentage': 0,
                            'timestamp': None}
        fake_host = host_manager.HostState('host1#_pool0')
        self.assertIsNone(fake_host.free_capacity_gb)

        fake_host.update_from_share_capability(share_capability)
        # Backend level stats remain uninitialized
        self.assertEqual(fake_host.total_capacity_gb, 0)
        self.assertIsNone(fake_host.free_capacity_gb)
        # Pool stats has been updated
        self.assertEqual(fake_host.pools['_pool0'].total_capacity_gb,
                         'infinite')
        self.assertEqual(fake_host.pools['_pool0'].free_capacity_gb,
                         'infinite')

    def test_update_from_share_unknown_capability(self):
        share_capability = {
            'total_capacity_gb': 'infinite',
            'free_capacity_gb': 'unknown',
            'reserved_percentage': 0,
            'timestamp': None
        }
        fake_host = host_manager.HostState('host1#_pool0')
        self.assertIsNone(fake_host.free_capacity_gb)

        fake_host.update_from_share_capability(share_capability)
        # Backend level stats remain uninitialized
        self.assertEqual(fake_host.total_capacity_gb, 0)
        self.assertIsNone(fake_host.free_capacity_gb)
        # Pool stats has been updated
        self.assertEqual(fake_host.pools['_pool0'].total_capacity_gb,
                         'infinite')
        self.assertEqual(fake_host.pools['_pool0'].free_capacity_gb,
                         'unknown')

    def test_consume_from_share_capability(self):
        share_size = 10
        free_capacity = 100
        fake_share = {'id': 'foo', 'size': share_size}
        share_capability = {
            'total_capacity_gb': free_capacity * 2,
            'free_capacity_gb': free_capacity,
            'reserved_percentage': 0,
            'timestamp': None
        }
        fake_host = host_manager.PoolState('host1', share_capability, '_pool0')

        fake_host.update_from_share_capability(share_capability)
        fake_host.consume_from_share(fake_share)
        self.assertEqual(fake_host.free_capacity_gb,
                         free_capacity - share_size)

    def test_consume_from_share_infinite_capability(self):
        share_capability = {
            'total_capacity_gb': 'infinite',
            'free_capacity_gb': 'infinite',
            'reserved_percentage': 0,
            'timestamp': None
        }
        fake_host = host_manager.PoolState('host1', share_capability, '_pool0')
        share_size = 1000
        fake_share = {'id': 'foo', 'size': share_size}

        fake_host.update_from_share_capability(share_capability)
        fake_host.consume_from_share(fake_share)
        self.assertEqual(fake_host.total_capacity_gb, 'infinite')
        self.assertEqual(fake_host.free_capacity_gb, 'infinite')

    def test_consume_from_share_unknown_capability(self):
        share_capability = {
            'total_capacity_gb': 'infinite',
            'free_capacity_gb': 'unknown',
            'reserved_percentage': 0,
            'timestamp': None
        }
        fake_host = host_manager.PoolState('host1', share_capability, '_pool0')
        share_size = 1000
        fake_share = {'id': 'foo', 'size': share_size}

        fake_host.update_from_share_capability(share_capability)
        fake_host.consume_from_share(fake_share)
        self.assertEqual(fake_host.total_capacity_gb, 'infinite')
        self.assertEqual(fake_host.free_capacity_gb, 'unknown')

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
        }
        fake_host = host_manager.HostState('host1')
        fake_host.update_from_share_capability(capability)

        result = fake_host.__repr__()
        expected = "host: 'host1', free_capacity_gb: None, " \
                   "pools: {'Backend1': host: 'host1#Backend1', " \
                   "free_capacity_gb: 15000, pools: None}"
        self.assertEqual(expected, result)


class PoolStateTestCase(test.TestCase):
    """Test case for HostState class."""

    def test_update_from_share_capability(self):
        share_capability = {
            'total_capacity_gb': 1024,
            'free_capacity_gb': 512,
            'reserved_percentage': 0,
            'timestamp': None,
            'cap1': 'val1',
            'cap2': 'val2'
        }
        fake_pool = host_manager.PoolState('host1', None, 'pool0')
        self.assertIsNone(fake_pool.free_capacity_gb)

        fake_pool.update_from_share_capability(share_capability)
        self.assertEqual(fake_pool.host, 'host1#pool0')
        self.assertEqual(fake_pool.pool_name, 'pool0')
        self.assertEqual(fake_pool.total_capacity_gb, 1024)
        self.assertEqual(fake_pool.free_capacity_gb, 512)

        self.assertDictMatch(fake_pool.capabilities, share_capability)
