# Copyright 2015 Mirantis, Inc.
# All Rights Reserved
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
import netaddr
from oslo_config import cfg
import six

from manila.common import constants
from manila import context
from manila import exception
from manila.network import standalone_network_plugin as plugin
from manila import test
from manila.tests import utils as test_utils

CONF = cfg.CONF

fake_context = context.RequestContext(
    user_id='fake user', project_id='fake project', is_admin=False)
fake_share_server = dict(id='fake_share_server_id')
fake_share_network = dict(id='fake_share_network_id')


@ddt.ddt
class StandaloneNetworkPluginTest(test.TestCase):

    @ddt.data('custom_config_group_name', 'DEFAULT')
    def test_init_only_with_required_data_v4(self, group_name):
        data = {
            group_name: {
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '24',
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin(
                config_group_name=group_name)

        self.assertEqual('10.0.0.1', instance.gateway)
        self.assertEqual('24', instance.mask)
        self.assertIsNone(instance.segmentation_id)
        self.assertIsNone(instance.allowed_ip_ranges)
        self.assertEqual(4, instance.ip_version)
        self.assertEqual(netaddr.IPNetwork('10.0.0.1/24'), instance.net)
        self.assertEqual(['10.0.0.1/24'], instance.allowed_cidrs)
        self.assertEqual(
            ('10.0.0.0', '10.0.0.1', '10.0.0.255'),
            instance.reserved_addresses)

    @ddt.data('custom_config_group_name', 'DEFAULT')
    def test_init_with_all_data_v4(self, group_name):
        data = {
            group_name: {
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '255.255.0.0',
                'standalone_network_plugin_network_type': 'vlan',
                'standalone_network_plugin_segmentation_id': 1001,
                'standalone_network_plugin_allowed_ip_ranges': (
                    '10.0.0.3-10.0.0.7,10.0.0.69-10.0.0.157,10.0.0.213'),
                'network_plugin_ipv4_enabled': True,
            },
        }
        allowed_cidrs = [
            '10.0.0.3/32', '10.0.0.4/30', '10.0.0.69/32', '10.0.0.70/31',
            '10.0.0.72/29', '10.0.0.80/28', '10.0.0.96/27', '10.0.0.128/28',
            '10.0.0.144/29', '10.0.0.152/30', '10.0.0.156/31', '10.0.0.213/32',
        ]
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin(
                config_group_name=group_name)

        self.assertEqual(4, instance.ip_version)
        self.assertEqual('10.0.0.1', instance.gateway)
        self.assertEqual('255.255.0.0', instance.mask)
        self.assertEqual('vlan', instance.network_type)
        self.assertEqual(1001, instance.segmentation_id)
        self.assertEqual(allowed_cidrs, instance.allowed_cidrs)
        self.assertEqual(
            ['10.0.0.3-10.0.0.7', '10.0.0.69-10.0.0.157', '10.0.0.213'],
            instance.allowed_ip_ranges)
        self.assertEqual(
            netaddr.IPNetwork('10.0.0.1/255.255.0.0'), instance.net)
        self.assertEqual(
            ('10.0.0.0', '10.0.0.1', '10.0.255.255'),
            instance.reserved_addresses)

    @ddt.data('custom_config_group_name', 'DEFAULT')
    def test_init_only_with_required_data_v6(self, group_name):
        data = {
            group_name: {
                'standalone_network_plugin_gateway': (
                    '2001:cdba::3257:9652'),
                'standalone_network_plugin_mask': '48',
                'network_plugin_ipv6_enabled': True,
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin(
                config_group_name=group_name)

        self.assertEqual(
            '2001:cdba::3257:9652', instance.gateway)
        self.assertEqual('48', instance.mask)
        self.assertIsNone(instance.segmentation_id)
        self.assertIsNone(instance.allowed_ip_ranges)
        self.assertEqual(6, instance.ip_version)
        self.assertEqual(
            netaddr.IPNetwork('2001:cdba::3257:9652/48'),
            instance.net)
        self.assertEqual(
            ['2001:cdba::3257:9652/48'], instance.allowed_cidrs)
        self.assertEqual(
            ('2001:cdba::', '2001:cdba::3257:9652',
             netaddr.IPAddress('2001:cdba:0:ffff:ffff:ffff:ffff:ffff').format()
             ),
            instance.reserved_addresses)

    @ddt.data('custom_config_group_name', 'DEFAULT')
    def test_init_with_all_data_v6(self, group_name):
        data = {
            group_name: {
                'standalone_network_plugin_gateway': '2001:db8::0001',
                'standalone_network_plugin_mask': '88',
                'standalone_network_plugin_network_type': 'vlan',
                'standalone_network_plugin_segmentation_id': 3999,
                'standalone_network_plugin_allowed_ip_ranges': (
                    '2001:db8::-2001:db8:0000:0000:0000:007f:ffff:ffff'),
                'network_plugin_ipv6_enabled': True,
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin(
                config_group_name=group_name)

        self.assertEqual(6, instance.ip_version)
        self.assertEqual('2001:db8::0001', instance.gateway)
        self.assertEqual('88', instance.mask)
        self.assertEqual('vlan', instance.network_type)
        self.assertEqual(3999, instance.segmentation_id)
        self.assertEqual(['2001:db8::/89'], instance.allowed_cidrs)
        self.assertEqual(
            ['2001:db8::-2001:db8:0000:0000:0000:007f:ffff:ffff'],
            instance.allowed_ip_ranges)
        self.assertEqual(
            netaddr.IPNetwork('2001:db8::0001/88'), instance.net)
        self.assertEqual(
            ('2001:db8::', '2001:db8::0001', '2001:db8::ff:ffff:ffff'),
            instance.reserved_addresses)

    @ddt.data('flat', 'vlan', 'vxlan', 'gre')
    def test_init_with_valid_network_types_v4(self, network_type):
        data = {
            'DEFAULT': {
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '255.255.0.0',
                'standalone_network_plugin_network_type': network_type,
                'standalone_network_plugin_segmentation_id': 1001,
                'network_plugin_ipv4_enabled': True,
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin(
                config_group_name='DEFAULT')

            self.assertEqual(instance.network_type, network_type)

    @ddt.data(
        'foo', 'foovlan', 'vlanfoo', 'foovlanbar', 'None', 'Vlan', 'vlaN')
    def test_init_with_fake_network_types_v4(self, fake_network_type):
        data = {
            'DEFAULT': {
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '255.255.0.0',
                'standalone_network_plugin_network_type': fake_network_type,
                'standalone_network_plugin_segmentation_id': 1001,
                'network_plugin_ipv4_enabled': True,
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            self.assertRaises(
                cfg.ConfigFileValueError,
                plugin.StandaloneNetworkPlugin,
                config_group_name='DEFAULT',
            )

    @ddt.data('custom_config_group_name', 'DEFAULT')
    def test_invalid_init_without_any_config_definitions(self, group_name):
        self.assertRaises(
            exception.NetworkBadConfigurationException,
            plugin.StandaloneNetworkPlugin,
            config_group_name=group_name)

    @ddt.data(
        {},
        {'gateway': '20.0.0.1'},
        {'mask': '8'},
        {'gateway': '20.0.0.1', 'mask': '33'},
        {'gateway': '20.0.0.256', 'mask': '16'})
    def test_invalid_init_required_data_improper(self, data):
        group_name = 'custom_group_name'
        if 'gateway' in data:
            data['standalone_network_plugin_gateway'] = data.pop('gateway')
        if 'mask' in data:
            data['standalone_network_plugin_mask'] = data.pop('mask')
        data = {group_name: data}
        with test_utils.create_temp_config_with_opts(data):
            self.assertRaises(
                exception.NetworkBadConfigurationException,
                plugin.StandaloneNetworkPlugin,
                config_group_name=group_name)

    @ddt.data(
        'fake',
        '11.0.0.0-11.0.0.5-11.0.0.11',
        '11.0.0.0-11.0.0.5',
        '10.0.10.0-10.0.10.5',
        '10.0.0.0-10.0.0.5,fake',
        '10.0.10.0-10.0.10.5,10.0.0.0-10.0.0.5',
        '10.0.10.0-10.0.10.5,10.0.0.10-10.0.10.5',
        '10.0.0.0-10.0.0.5,10.0.10.0-10.0.10.5')
    def test_invalid_init_incorrect_allowed_ip_ranges_v4(self, ip_range):
        group_name = 'DEFAULT'
        data = {
            group_name: {
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '255.255.255.0',
                'standalone_network_plugin_allowed_ip_ranges': ip_range,
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            self.assertRaises(
                exception.NetworkBadConfigurationException,
                plugin.StandaloneNetworkPlugin,
                config_group_name=group_name)

    @ddt.data(
        {'gateway': '2001:db8::0001', 'vers': 4},
        {'gateway': '10.0.0.1', 'vers': 6})
    @ddt.unpack
    def test_invalid_init_mismatch_of_versions(self, gateway, vers):
        group_name = 'DEFAULT'
        data = {
            group_name: {
                'standalone_network_plugin_gateway': gateway,
                'standalone_network_plugin_mask': '25',
            },
        }
        if vers == 4:
            data[group_name]['network_plugin_ipv4_enabled'] = True
        if vers == 6:
            data[group_name]['network_plugin_ipv4_enabled'] = False
            data[group_name]['network_plugin_ipv6_enabled'] = True

        with test_utils.create_temp_config_with_opts(data):
            self.assertRaises(
                exception.NetworkBadConfigurationException,
                plugin.StandaloneNetworkPlugin,
                config_group_name=group_name)

    def test_deallocate_network(self):
        share_server_id = 'fake_share_server_id'
        data = {
            'DEFAULT': {
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '24',
            },
        }
        fake_allocations = [{'id': 'fake1'}, {'id': 'fake2'}]
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin()
        self.mock_object(
            instance.db, 'network_allocations_get_for_share_server',
            mock.Mock(return_value=fake_allocations))
        self.mock_object(instance.db, 'network_allocation_delete')

        instance.deallocate_network(fake_context, share_server_id)

        (instance.db.network_allocations_get_for_share_server.
            assert_called_once_with(fake_context, share_server_id))
        (instance.db.network_allocation_delete.
            assert_has_calls([
                mock.call(fake_context, 'fake1'),
                mock.call(fake_context, 'fake2'),
            ]))

    def test_allocate_network_zero_addresses_ipv4(self):
        data = {
            'DEFAULT': {
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '24',
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin()
        self.mock_object(instance.db, 'share_network_update')

        allocations = instance.allocate_network(
            fake_context, fake_share_server, fake_share_network, count=0)

        self.assertEqual([], allocations)
        instance.db.share_network_update.assert_called_once_with(
            fake_context, fake_share_network['id'],
            dict(network_type=None, segmentation_id=None,
                 cidr=six.text_type(instance.net.cidr),
                 gateway=six.text_type(instance.gateway),
                 ip_version=4,
                 mtu=1500))

    def test_allocate_network_zero_addresses_ipv6(self):
        data = {
            'DEFAULT': {
                'standalone_network_plugin_gateway': '2001:db8::0001',
                'standalone_network_plugin_mask': '64',
                'network_plugin_ipv6_enabled': True,
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin()
        self.mock_object(instance.db, 'share_network_update')

        allocations = instance.allocate_network(
            fake_context, fake_share_server, fake_share_network, count=0)

        self.assertEqual([], allocations)
        instance.db.share_network_update.assert_called_once_with(
            fake_context, fake_share_network['id'],
            dict(network_type=None, segmentation_id=None,
                 cidr=six.text_type(instance.net.cidr),
                 gateway=six.text_type(instance.gateway),
                 ip_version=6,
                 mtu=1500))

    def test_allocate_network_one_ip_address_ipv4_no_usages_exist(self):
        data = {
            'DEFAULT': {
                'standalone_network_plugin_network_type': 'vlan',
                'standalone_network_plugin_segmentation_id': 1003,
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '24',
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin()
        self.mock_object(instance.db, 'share_network_update')
        self.mock_object(instance.db, 'network_allocation_create')
        self.mock_object(
            instance.db, 'network_allocations_get_by_ip_address',
            mock.Mock(return_value=[]))

        allocations = instance.allocate_network(
            fake_context, fake_share_server, fake_share_network)

        self.assertEqual(1, len(allocations))
        na_data = {
            'network_type': 'vlan',
            'segmentation_id': 1003,
            'cidr': '10.0.0.0/24',
            'gateway': '10.0.0.1',
            'ip_version': 4,
            'mtu': 1500,
        }
        instance.db.share_network_update.assert_called_once_with(
            fake_context, fake_share_network['id'], na_data)
        instance.db.network_allocations_get_by_ip_address.assert_has_calls(
            [mock.call(fake_context, '10.0.0.2')])
        instance.db.network_allocation_create.assert_called_once_with(
            fake_context,
            dict(share_server_id=fake_share_server['id'],
                 ip_address='10.0.0.2', status=constants.STATUS_ACTIVE,
                 label='user', **na_data))

    def test_allocate_network_two_ip_addresses_ipv4_two_usages_exist(self):
        ctxt = type('FakeCtxt', (object,), {'fake': ['10.0.0.2', '10.0.0.4']})

        def fake_get_allocations_by_ip_address(context, ip_address):
            if ip_address not in context.fake:
                context.fake.append(ip_address)
                return []
            else:
                return context.fake

        data = {
            'DEFAULT': {
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '24',
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin()
        self.mock_object(instance.db, 'share_network_update')
        self.mock_object(instance.db, 'network_allocation_create')
        self.mock_object(
            instance.db, 'network_allocations_get_by_ip_address',
            mock.Mock(side_effect=fake_get_allocations_by_ip_address))

        allocations = instance.allocate_network(
            ctxt, fake_share_server, fake_share_network, count=2)

        self.assertEqual(2, len(allocations))
        na_data = {
            'network_type': None,
            'segmentation_id': None,
            'cidr': six.text_type(instance.net.cidr),
            'gateway': six.text_type(instance.gateway),
            'ip_version': 4,
            'mtu': 1500,
        }
        instance.db.share_network_update.assert_called_once_with(
            ctxt, fake_share_network['id'], dict(**na_data))
        instance.db.network_allocations_get_by_ip_address.assert_has_calls(
            [mock.call(ctxt, '10.0.0.2'), mock.call(ctxt, '10.0.0.3'),
             mock.call(ctxt, '10.0.0.4'), mock.call(ctxt, '10.0.0.5')])
        instance.db.network_allocation_create.assert_has_calls([
            mock.call(
                ctxt,
                dict(share_server_id=fake_share_server['id'],
                     ip_address='10.0.0.3', status=constants.STATUS_ACTIVE,
                     label='user', **na_data)),
            mock.call(
                ctxt,
                dict(share_server_id=fake_share_server['id'],
                     ip_address='10.0.0.5', status=constants.STATUS_ACTIVE,
                     label='user', **na_data)),
        ])

    def test_allocate_network_no_available_ipv4_addresses(self):
        data = {
            'DEFAULT': {
                'standalone_network_plugin_gateway': '10.0.0.1',
                'standalone_network_plugin_mask': '30',
            },
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.StandaloneNetworkPlugin()
        self.mock_object(instance.db, 'share_network_update')
        self.mock_object(instance.db, 'network_allocation_create')
        self.mock_object(
            instance.db, 'network_allocations_get_by_ip_address',
            mock.Mock(return_value=['not empty list']))

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            instance.allocate_network,
            fake_context, fake_share_server, fake_share_network)

        instance.db.share_network_update.assert_called_once_with(
            fake_context, fake_share_network['id'],
            dict(network_type=None, segmentation_id=None,
                 cidr=six.text_type(instance.net.cidr),
                 gateway=six.text_type(instance.gateway),
                 ip_version=4,
                 mtu=1500))
        instance.db.network_allocations_get_by_ip_address.assert_has_calls(
            [mock.call(fake_context, '10.0.0.2')])
