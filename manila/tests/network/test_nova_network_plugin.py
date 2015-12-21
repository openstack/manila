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

from manila import context
from manila import exception
from manila.network import nova_network_plugin as plugin
from manila import test
from manila.tests import utils as test_utils


@ddt.ddt
class NovaNetworkPluginTest(test.TestCase):

    def setUp(self):
        super(NovaNetworkPluginTest, self).setUp()
        self.fake_context = context.RequestContext(
            user_id='fake user', project_id='fake project', is_admin=False)
        self.instance = plugin.NovaNetworkPlugin()
        self.share_server = dict(id='fake_share_server_id')
        self.share_network = dict(
            id='fake_sn_id', nova_net_id='fake_nova_net_id')

    def test_allocate_network_get_zero(self):
        share_network = 'fake_share_network'

        allocations = self.instance.allocate_network(
            self.fake_context, self.share_server, share_network, count=0)

        self.assertEqual([], allocations)
        self.assertTrue(hasattr(self.instance, 'label'))
        self.assertEqual('user', self.instance.label)

    @ddt.data('flat', 'vlan')
    def test_allocate_network_get_one(self, net_type):
        def fake_get_ip_from_db(context, ip_addr):
            return [] if ip_addr != '20.0.0.7' else ['fake not empty list']

        def fake_fixed_ip_get(context, ip_addr):
            if ip_addr == '20.0.0.8':
                return dict(host='foo', hostname='bar')
            return dict(host=None, hostname=None)

        share_network = dict(id='fake_sn_id', nova_net_id='fake_nova_net_id')
        nova_net = dict(
            cidr='20.0.0.0/24', cidr_v6=None,
            gateway='20.0.0.1', gateway_v6=None,
            dhcp_server='20.0.0.2', broadcast='20.0.0.255',
            vpn_private_address='20.0.0.3', vpn_public_address='20.0.0.4',
            dns1='20.0.0.5', dns2='20.0.0.6', vlan=None)
        if net_type == 'vlan':
            nova_net['vlan'] = 100
        self.mock_object(self.instance.nova_api, 'fixed_ip_reserve')
        self.mock_object(
            self.instance.nova_api, 'fixed_ip_get',
            mock.Mock(side_effect=fake_fixed_ip_get))
        self.mock_object(
            self.instance.nova_api, 'network_get',
            mock.Mock(return_value=nova_net))
        self.mock_object(self.instance.db, 'share_network_update')
        self.mock_object(
            self.instance.db, 'network_allocations_get_by_ip_address',
            mock.Mock(side_effect=fake_get_ip_from_db))
        expected_ip_address = '20.0.0.9'

        allocations = self.instance.allocate_network(
            self.fake_context, self.share_server, share_network)

        self.assertEqual(1, len(allocations))
        self.assertEqual(
            self.share_server['id'], allocations[0]['share_server_id'])
        self.assertEqual(expected_ip_address, allocations[0]['ip_address'])
        self.instance.nova_api.network_get.assert_called_once_with(
            self.instance.admin_context, share_network['nova_net_id'])
        self.instance.nova_api.fixed_ip_reserve.assert_called_once_with(
            self.instance.admin_context, expected_ip_address)
        self.instance.db.share_network_update.assert_called_once_with(
            self.fake_context, share_network['id'],
            dict(cidr=nova_net['cidr'], ip_version=4,
                 segmentation_id=nova_net['vlan'], network_type=net_type))
        self.instance.db.network_allocations_get_by_ip_address.\
            assert_has_calls([
                mock.call(self.fake_context, '20.0.0.7'),
                mock.call(self.fake_context, '20.0.0.8'),
                mock.call(self.fake_context, '20.0.0.9')])
        self.instance.nova_api.fixed_ip_get.assert_has_calls([
            mock.call(self.instance.admin_context, '20.0.0.8'),
            mock.call(self.instance.admin_context, '20.0.0.9')])

    @ddt.data('flat', 'vlan')
    def test_allocate_network_get_two(self, net_type):
        def fake_get_ip_from_db(context, ip_addr):
            return [] if ip_addr != '20.0.0.7' else ['fake not empty list']

        def fake_fixed_ip_get(context, ip_addr):
            if ip_addr == '20.0.0.8':
                return dict(host='foo', hostname='bar')
            return dict(host=None, hostname=None)

        nova_net = dict(
            cidr='20.0.0.0/24', cidr_v6=None,
            gateway='20.0.0.1', gateway_v6=None,
            dhcp_server='20.0.0.254', broadcast='20.0.0.255',
            vpn_private_address='20.0.0.3', vpn_public_address='20.0.0.4',
            dns1='20.0.0.5', dns2='20.0.0.6', vlan=None)
        if net_type == 'vlan':
            nova_net['vlan'] = 100
        self.mock_object(self.instance.nova_api, 'fixed_ip_reserve')
        self.mock_object(
            self.instance.nova_api, 'fixed_ip_get',
            mock.Mock(side_effect=fake_fixed_ip_get))
        self.mock_object(
            self.instance.nova_api, 'network_get',
            mock.Mock(return_value=nova_net))
        self.mock_object(self.instance.db, 'share_network_update')
        self.mock_object(
            self.instance.db, 'network_allocations_get_by_ip_address',
            mock.Mock(side_effect=fake_get_ip_from_db))
        expected_ip_address1 = '20.0.0.2'
        expected_ip_address2 = '20.0.0.9'

        allocations = self.instance.allocate_network(
            self.fake_context, self.share_server, self.share_network, count=2)

        self.assertEqual(2, len(allocations))
        for allocation in allocations:
            self.assertEqual(
                self.share_server['id'], allocation['share_server_id'])
        self.assertEqual(expected_ip_address1, allocations[0]['ip_address'])
        self.assertEqual(expected_ip_address2, allocations[1]['ip_address'])
        self.instance.nova_api.network_get.assert_called_once_with(
            self.instance.admin_context, self.share_network['nova_net_id'])
        self.instance.nova_api.fixed_ip_reserve.assert_has_calls([
            mock.call(self.instance.admin_context, expected_ip_address1),
            mock.call(self.instance.admin_context, expected_ip_address2)])
        self.instance.db.share_network_update.assert_called_once_with(
            self.fake_context, self.share_network['id'],
            dict(cidr=nova_net['cidr'], ip_version=4,
                 segmentation_id=nova_net['vlan'], network_type=net_type))
        self.instance.db.network_allocations_get_by_ip_address.\
            assert_has_calls([
                mock.call(self.fake_context, '20.0.0.2'),
                mock.call(self.fake_context, '20.0.0.7'),
                mock.call(self.fake_context, '20.0.0.8'),
                mock.call(self.fake_context, '20.0.0.9')])
        self.instance.nova_api.fixed_ip_get.assert_has_calls([
            mock.call(self.instance.admin_context, '20.0.0.2'),
            mock.call(self.instance.admin_context, '20.0.0.8'),
            mock.call(self.instance.admin_context, '20.0.0.9')])

    def test_allocate_network_nova_net_id_no_available_ips_left(self):
        nova_net = dict(
            id='fake_net_id', cidr='20.0.0.0/24', cidr_v6=None,
            gateway='20.0.0.1', gateway_v6=None,
            dhcp_server='20.0.0.2', broadcast='20.0.0.255',
            vpn_private_address='20.0.0.3', vpn_public_address='20.0.0.4',
            dns1='20.0.0.5', dns2='20.0.0.6', vlan=100)
        self.mock_object(
            self.instance.nova_api, 'network_get',
            mock.Mock(return_value=nova_net))
        self.mock_object(self.instance.db, 'share_network_update')
        self.mock_object(
            self.instance.db, 'network_allocations_get_by_ip_address',
            mock.Mock(return_value=['fake not empty list']))

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            self.instance.allocate_network,
            self.fake_context, self.share_server, self.share_network)

        self.instance.nova_api.network_get.assert_called_once_with(
            self.instance.admin_context, self.share_network['nova_net_id'])
        self.instance.db.share_network_update.assert_called_once_with(
            self.fake_context, self.share_network['id'],
            dict(cidr=nova_net['cidr'], ip_version=4,
                 segmentation_id=nova_net['vlan'], network_type='vlan'))
        self.assertEqual(
            248,
            self.instance.db.network_allocations_get_by_ip_address.call_count)

    @ddt.data(dict(), dict(nova_net_id=None))
    def test_allocate_network_nova_net_id_is_not_provided(self, share_network):
        self.assertRaises(
            exception.NetworkException,
            self.instance.allocate_network,
            self.fake_context, self.share_server, share_network)

    def test_deallocate_network(self):
        fake_alloc = dict(id='fake_alloc_id', ip_address='fake_ip_address')
        self.mock_object(self.instance.nova_api, 'fixed_ip_unreserve')
        self.mock_object(self.instance.db, 'network_allocation_delete')
        self.mock_object(
            self.instance.db, 'network_allocations_get_for_share_server',
            mock.Mock(return_value=[fake_alloc]))

        self.instance.deallocate_network(
            self.fake_context, self.share_server['id'])

        self.instance.db.network_allocations_get_for_share_server.\
            assert_called_once_with(
                self.fake_context, self.share_server['id'])
        self.instance.db.network_allocation_delete.assert_called_once_with(
            self.fake_context, fake_alloc['id'])
        self.instance.nova_api.fixed_ip_unreserve.assert_called_once_with(
            self.instance.admin_context, fake_alloc['ip_address'])


@ddt.ddt
class NovaSingleNetworkPluginTest(test.TestCase):

    def setUp(self):
        super(NovaSingleNetworkPluginTest, self).setUp()
        self.share_server = dict(id='fake_share_server_id')
        self.context = context.RequestContext(
            user_id='fake user', project_id='fake project', is_admin=False)

    def _get_instance(self, label=None):
        nova_net_id = 'fake_nova_net_id'
        config_data = dict(
            DEFAULT=dict(nova_single_network_plugin_net_id=nova_net_id))
        with test_utils.create_temp_config_with_opts(config_data):
            return plugin.NovaSingleNetworkPlugin(label=label)

    def test_init_valid(self):
        nova_net_id = 'fake_nova_net_id'
        config_data = dict(
            DEFAULT=dict(nova_single_network_plugin_net_id=nova_net_id))
        with test_utils.create_temp_config_with_opts(config_data):
            instance = plugin.NovaSingleNetworkPlugin()
        self.assertEqual(nova_net_id, instance.net_id)

    @ddt.data(dict(), dict(net=''))
    def test_init_invalid(self, data):
        config_data = dict(DEFAULT=data)
        with test_utils.create_temp_config_with_opts(config_data):
            self.assertRaises(
                exception.NetworkBadConfigurationException,
                plugin.NovaSingleNetworkPlugin)

    def test_allocate_network_net_is_not_set_in_share_network(self):
        instance = self._get_instance()
        share_network = dict(id='fake_share_network')
        updated_share_network = dict(id='fake_updated_share_network')
        allocations = ['foo', 'bar']
        self.mock_object(
            instance.db, 'share_network_update',
            mock.Mock(return_value=updated_share_network))
        self.mock_object(
            instance, '_allocate_network', mock.Mock(return_value=allocations))

        result = instance.allocate_network(
            self.context, self.share_server, share_network, count=2)

        self.assertEqual(allocations, result)
        instance.db.share_network_update.assert_called_once_with(
            self.context, share_network['id'],
            dict(nova_net_id='fake_nova_net_id'))
        instance._allocate_network.assert_called_once_with(
            self.context, self.share_server, updated_share_network, count=2)

    def test_allocate_network_net_is_set_in_share_network(self):
        instance = self._get_instance()
        share_network = dict(
            id='fake_share_network', nova_net_id='fake_nova_net_id')
        allocations = ['foo', 'bar']
        self.mock_object(instance.db, 'share_network_update')
        self.mock_object(
            instance, '_allocate_network', mock.Mock(return_value=allocations))

        result = instance.allocate_network(
            self.context, self.share_server, share_network, count=2)

        self.assertEqual(allocations, result)
        instance.db.share_network_update.assert_has_calls([])
        instance._allocate_network.assert_called_once_with(
            self.context, self.share_server, share_network, count=2)

    def test_allocate_network_with_admin_label(self):
        instance = self._get_instance(label='admin')
        allocations = ['foo', 'bar']
        self.mock_object(instance.db, 'share_network_update')
        self.mock_object(
            instance, '_allocate_network', mock.Mock(return_value=allocations))
        fake_share_network = {'nova_net_id': 'fake_nova_net_id'}

        result = instance.allocate_network(
            self.context, self.share_server, fake_share_network, count=2)

        self.assertTrue(hasattr(instance, 'label'))
        self.assertEqual('admin', instance.label)
        self.assertEqual(allocations, result)
        instance.db.share_network_update.assert_has_calls([])
        instance._allocate_network.assert_called_once_with(
            self.context, self.share_server, fake_share_network, count=2)

    def test_allocate_network_different_nova_net_id_is_set(self):
        instance = self._get_instance()
        share_network = dict(
            id='fake_share_network', nova_net_id='foobar')
        self.mock_object(instance.db, 'share_network_update')
        self.mock_object(instance, '_allocate_network')

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            instance.allocate_network,
            self.context, self.share_server, share_network, count=3)

        instance.db.share_network_update.assert_has_calls([])
        instance._allocate_network.assert_has_calls([])

    @ddt.data(
        dict(id='foo', neutron_net_id='bar'),
        dict(id='foo', neutron_subnet_id='quuz'),
        dict(id='foo', neutron_net_id='bar', neutron_subnet_id='quuz'))
    def test_allocate_network_neutron_data_exist(self, sn):
        instance = self._get_instance()
        self.mock_object(instance.db, 'share_network_update')
        self.mock_object(instance, '_allocate_network')

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            instance.allocate_network,
            self.context, self.share_server, sn, count=3)

        instance.db.share_network_update.assert_has_calls([])
        instance._allocate_network.assert_has_calls([])
