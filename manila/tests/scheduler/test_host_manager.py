# Copyright (c) 2011 OpenStack, LLC
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
from oslo.config import cfg
from oslo.utils import timeutils

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
                           for x in xrange(1, 5)]

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

        # Test 'volume' returns 1 correct function
        filter_classes = self.host_manager._choose_host_filters(None)
        self.assertEqual(len(filter_classes), 1)
        self.assertEqual(filter_classes[0].__name__, 'FakeFilterClass2')

    def _verify_result(self, info, result):
        for x in info['got_fprops']:
            self.assertEqual(x, info['expected_fprops'])
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

            self.stubs.Set(FakeFilterClass1, '_filter_one', fake_filter_one)
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
        self.assertEqual(self.host_manager.service_states, service_states)
        # Make sure original dictionary wasn't copied
        self.assertEqual(host1_share_capabs['timestamp'], 1)

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

            self.assertEqual(len(host_state_map), 4)
            # Check that service is up
            for i in xrange(4):
                share_node = fakes.SHARE_SERVICES[i]
                host = share_node['host']
                self.assertEqual(host_state_map[host].service, share_node)
            db.service_get_all_by_topic.assert_called_once_with(context, topic)


class HostStateTestCase(test.TestCase):
    """Test case for HostState class."""

    def test_update_from_share_capability(self):
        fake_host = host_manager.HostState('host1')
        self.assertEqual(fake_host.free_capacity_gb, None)

        share_capability = {'total_capacity_gb': 1024,
                            'free_capacity_gb': 512,
                            'reserved_percentage': 0,
                            'timestamp': None}

        fake_host.update_from_share_capability(share_capability)
        self.assertEqual(fake_host.free_capacity_gb, 512)

    def test_update_from_share_infinite_capability(self):
        fake_host = host_manager.HostState('host1')
        self.assertEqual(fake_host.free_capacity_gb, None)

        share_capability = {'total_capacity_gb': 'infinite',
                            'free_capacity_gb': 'infinite',
                            'reserved_percentage': 0,
                            'timestamp': None}

        fake_host.update_from_share_capability(share_capability)
        self.assertEqual(fake_host.total_capacity_gb, 'infinite')
        self.assertEqual(fake_host.free_capacity_gb, 'infinite')

    def test_update_from_share_unknown_capability(self):
        fake_host = host_manager.HostState('host1')
        self.assertEqual(fake_host.free_capacity_gb, None)

        share_capability = {
            'total_capacity_gb': 'infinite',
            'free_capacity_gb': 'unknown',
            'reserved_percentage': 0,
            'timestamp': None
        }

        fake_host.update_from_share_capability(share_capability)
        self.assertEqual(fake_host.total_capacity_gb, 'infinite')
        self.assertEqual(fake_host.free_capacity_gb, 'unknown')

    def test_consume_from_share_capability(self):
        fake_host = host_manager.HostState('host1')
        share_size = 10
        free_capacity = 100
        fake_share = {'id': 'foo', 'size': share_size}

        share_capability = {
            'total_capacity_gb': free_capacity * 2,
            'free_capacity_gb': free_capacity,
            'reserved_percentage': 0,
            'timestamp': None
        }

        fake_host.update_from_share_capability(share_capability)
        fake_host.consume_from_share(fake_share)
        self.assertEqual(fake_host.free_capacity_gb,
                         free_capacity - share_size)

    def test_consume_from_share_infinite_capability(self):
        fake_host = host_manager.HostState('host1')
        share_size = 1000
        fake_share = {'id': 'foo', 'size': share_size}

        share_capability = {
            'total_capacity_gb': 'infinite',
            'free_capacity_gb': 'infinite',
            'reserved_percentage': 0,
            'timestamp': None
        }

        fake_host.update_from_share_capability(share_capability)
        fake_host.consume_from_share(fake_share)
        self.assertEqual(fake_host.total_capacity_gb, 'infinite')
        self.assertEqual(fake_host.free_capacity_gb, 'infinite')

    def test_consume_from_share_unknown_capability(self):
        fake_host = host_manager.HostState('host1')
        share_size = 1000
        fake_share = {'id': 'foo', 'size': share_size}

        share_capability = {
            'total_capacity_gb': 'infinite',
            'free_capacity_gb': 'unknown',
            'reserved_percentage': 0,
            'timestamp': None
        }

        fake_host.update_from_share_capability(share_capability)
        fake_host.consume_from_share(fake_share)
        self.assertEqual(fake_host.total_capacity_gb, 'infinite')
        self.assertEqual(fake_host.free_capacity_gb, 'unknown')
