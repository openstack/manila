# Copyright 2013 OpenStack Foundation
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

import copy
import time
from unittest import mock

import ddt
from oslo_config import cfg

from manila.common import constants
from manila import context
from manila.db import api as db_api
from manila import exception
from manila.network.neutron import api as neutron_api
from manila.network.neutron import constants as neutron_constants
from manila.network.neutron import neutron_network_plugin as plugin
from manila import test
from manila.tests import utils as test_utils

CONF = cfg.CONF

fake_neutron_port = {
    "status": "ACTIVE",
    "allowed_address_pairs": [],
    "admin_state_up": True,
    "network_id": "test_net_id",
    "tenant_id": "fake_tenant_id",
    "extra_dhcp_opts": [],
    "device_owner": "test",
    "binding:capabilities": {"port_filter": True},
    "mac_address": "test_mac",
    "fixed_ips": [
        {"subnet_id": "test_subnet_id", "ip_address": "203.0.113.100"},
    ],
    "id": "test_port_id",
    "security_groups": ["fake_sec_group_id"],
    "device_id": "fake_device_id",
}

fake_neutron_network = {
    'admin_state_up': True,
    'availability_zone_hints': [],
    'availability_zones': ['nova'],
    'description': '',
    'id': 'fake net id',
    'ipv4_address_scope': None,
    'ipv6_address_scope': None,
    'name': 'test_neutron_network',
    'port_security_enabled': True,
    'provider:network_type': 'vxlan',
    'provider:physical_network': None,
    'provider:segmentation_id': 1234,
    'router:external': False,
    'shared': False,
    'status': 'ACTIVE',
    'subnets': ['fake subnet id',
                'fake subnet id 2'],
}

fake_ip_version = 4

fake_neutron_subnet = {
    'cidr': '10.0.0.0/24',
    'ip_version': fake_ip_version,
    'gateway_ip': '10.0.0.1',
}

fake_share_network_subnet = {
    'id': 'fake nw subnet id',
    'neutron_subnet_id': fake_neutron_network['subnets'][0],
    'neutron_net_id': fake_neutron_network['id'],
    'network_type': 'fake_network_type',
    'segmentation_id': 1234,
    'ip_version': 4,
    'cidr': 'fake_cidr',
    'gateway': 'fake_gateway',
    'mtu': 1509,
}

fake_share_network = {
    'id': 'fake nw info id',
    'project_id': 'fake project id',
    'status': 'test_subnet_status',
    'name': 'fake name',
    'description': 'fake description',
    'security_services': [],
    'subnets': [fake_share_network_subnet],
}

fake_share_server = {
    'id': 'fake nw info id',
    'status': 'test_server_status',
    'host': 'fake@host',
    'network_allocations': [],
    'shares': [],
}

fake_network_allocation = {
    'id': fake_neutron_port['id'],
    'share_server_id': fake_share_server['id'],
    'ip_address': fake_neutron_port['fixed_ips'][0]['ip_address'],
    'mac_address': fake_neutron_port['mac_address'],
    'status': constants.STATUS_ACTIVE,
    'label': 'user',
    'network_type': fake_share_network_subnet['network_type'],
    'segmentation_id': fake_share_network_subnet['segmentation_id'],
    'ip_version': fake_share_network_subnet['ip_version'],
    'cidr': fake_share_network_subnet['cidr'],
    'gateway': fake_share_network_subnet['gateway'],
    'mtu': 1509,
    'share_network_subnet_id': fake_share_network_subnet['id'],
}

fake_nw_info = {
    'segments': [
        {
            'provider:network_type': 'vlan',
            'provider:physical_network': 'net1',
            'provider:segmentation_id': 3926,
        },
        {
            'provider:network_type': 'vxlan',
            'provider:physical_network': None,
            'provider:segmentation_id': 2000,
        },
    ],
    'mtu': 1509,
}

fake_neutron_network_multi = {
    'admin_state_up': True,
    'availability_zone_hints': [],
    'availability_zones': ['nova'],
    'description': '',
    'id': 'fake net id',
    'ipv4_address_scope': None,
    'ipv6_address_scope': None,
    'name': 'test_neutron_network',
    'port_security_enabled': True,
    'router:external': False,
    'shared': False,
    'status': 'ACTIVE',
    'subnets': ['fake subnet id',
                'fake subnet id 2'],
    'segments': fake_nw_info['segments'],
    'mtu': fake_nw_info['mtu'],
}

fake_share_network_multi = {
    'id': 'fake nw info id',
    'neutron_subnet_id': fake_neutron_network_multi['subnets'][0],
    'neutron_net_id': fake_neutron_network_multi['id'],
    'project_id': 'fake project id',
    'status': 'test_subnet_status',
    'name': 'fake name',
    'description': 'fake description',
    'security_services': [],
    'ip_version': None,
    'cidr': 'fake_cidr',
    'gateway': 'fake_gateway',
    'mtu': fake_neutron_network_multi['mtu'] - 1,
}

fake_network_allocation_multi = {
    'id': fake_neutron_port['id'],
    'share_server_id': fake_share_server['id'],
    'ip_address': fake_neutron_port['fixed_ips'][0]['ip_address'],
    'mac_address': fake_neutron_port['mac_address'],
    'status': constants.STATUS_ACTIVE,
    'label': 'user',
    'network_type': None,
    'segmentation_id': None,
    'ip_version': fake_neutron_subnet['ip_version'],
    'cidr': fake_neutron_subnet['cidr'],
    'gateway': fake_neutron_subnet['gateway_ip'],
    'mtu': fake_neutron_network_multi['mtu'],
    'share_network_subnet_id': fake_share_network['id'],
}

fake_binding_profile = {
    'neutron_switch_id': 'fake switch id',
    'neutron_port_id': 'fake port id',
    'neutron_switch_info': 'fake switch info'
}


@ddt.ddt
class NeutronNetworkPluginTest(test.TestCase):

    def setUp(self):
        super(NeutronNetworkPluginTest, self).setUp()
        self.plugin = self._get_neutron_network_plugin_instance()
        self.plugin.db = db_api
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)

    def _get_neutron_network_plugin_instance(self, config_data=None):
        if config_data is None:
            return plugin.NeutronNetworkPlugin()
        with test_utils.create_temp_config_with_opts(config_data):
            return plugin.NeutronNetworkPlugin()

    @mock.patch.object(db_api, 'network_allocation_create',
                       mock.Mock(return_values=fake_network_allocation))
    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test_allocate_network_one_allocation(self):
        has_provider_nw_ext = mock.patch.object(
            self.plugin, '_has_provider_network_extension').start()
        has_provider_nw_ext.return_value = True
        save_nw_data = mock.patch.object(self.plugin,
                                         '_save_neutron_network_data').start()
        save_subnet_data = mock.patch.object(
            self.plugin,
            '_save_neutron_subnet_data').start()

        with mock.patch.object(self.plugin.neutron_api, 'create_port',
                               mock.Mock(return_value=fake_neutron_port)):
            self.plugin.allocate_network(
                self.fake_context,
                fake_share_server,
                fake_share_network,
                fake_share_network_subnet,
                allocation_info={'count': 1})

            has_provider_nw_ext.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network_subnet,
                                                 save_db=True)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network_subnet,
                                                     save_db=True)
            self.plugin.neutron_api.create_port.assert_called_once_with(
                fake_share_network['project_id'],
                network_id=fake_share_network_subnet['neutron_net_id'],
                subnet_id=fake_share_network_subnet['neutron_subnet_id'],
                device_owner='manila:share',
                device_id=fake_share_network['id'])
            db_api.network_allocation_create.assert_called_once_with(
                self.fake_context,
                fake_network_allocation)

            has_provider_nw_ext.stop()
            save_nw_data.stop()
            save_subnet_data.stop()

    @mock.patch.object(db_api, 'network_allocation_create',
                       mock.Mock(return_values=fake_network_allocation))
    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test_allocate_network_two_allocation(self):
        has_provider_nw_ext = mock.patch.object(
            self.plugin, '_has_provider_network_extension').start()
        has_provider_nw_ext.return_value = True
        save_nw_data = mock.patch.object(self.plugin,
                                         '_save_neutron_network_data').start()
        save_subnet_data = mock.patch.object(
            self.plugin,
            '_save_neutron_subnet_data').start()

        with mock.patch.object(self.plugin.neutron_api, 'create_port',
                               mock.Mock(return_value=fake_neutron_port)):
            self.plugin.allocate_network(
                self.fake_context, fake_share_server, fake_share_network,
                fake_share_network_subnet, count=2)

            neutron_api_calls = [
                mock.call(
                    fake_share_network['project_id'],
                    network_id=fake_share_network_subnet['neutron_net_id'],
                    subnet_id=fake_share_network_subnet['neutron_subnet_id'],
                    device_owner='manila:share',
                    device_id=fake_share_network['id']),
                mock.call(
                    fake_share_network['project_id'],
                    network_id=fake_share_network_subnet['neutron_net_id'],
                    subnet_id=fake_share_network_subnet['neutron_subnet_id'],
                    device_owner='manila:share',
                    device_id=fake_share_network['id']),
            ]
            db_api_calls = [
                mock.call(self.fake_context, fake_network_allocation),
                mock.call(self.fake_context, fake_network_allocation)
            ]
            self.plugin.neutron_api.create_port.assert_has_calls(
                neutron_api_calls)
            db_api.network_allocation_create.assert_has_calls(db_api_calls)

            has_provider_nw_ext.stop()
            save_nw_data.stop()
            save_subnet_data.stop()

    @mock.patch.object(db_api, 'share_network_update', mock.Mock())
    def test_allocate_network_create_port_exception(self):
        has_provider_nw_ext = mock.patch.object(
            self.plugin, '_has_provider_network_extension').start()
        has_provider_nw_ext.return_value = True
        save_nw_data = mock.patch.object(self.plugin,
                                         '_save_neutron_network_data').start()
        save_subnet_data = mock.patch.object(
            self.plugin,
            '_save_neutron_subnet_data').start()
        create_port = mock.patch.object(self.plugin.neutron_api,
                                        'create_port').start()
        create_port.side_effect = exception.NetworkException

        self.assertRaises(exception.NetworkException,
                          self.plugin.allocate_network,
                          self.fake_context,
                          fake_share_server,
                          fake_share_network)

        has_provider_nw_ext.stop()
        save_nw_data.stop()
        save_subnet_data.stop()
        create_port.stop()

    def _setup_manage_network_allocations(self):

        allocations = ['192.168.0.11', '192.168.0.12', 'fd12::2000']

        neutron_ports = [
            copy.deepcopy(fake_neutron_port), copy.deepcopy(fake_neutron_port),
            copy.deepcopy(fake_neutron_port), copy.deepcopy(fake_neutron_port),
        ]

        neutron_ports[0]['fixed_ips'][0]['ip_address'] = '192.168.0.10'
        neutron_ports[0]['id'] = 'fake_port_id_0'
        neutron_ports[1]['fixed_ips'][0]['ip_address'] = '192.168.0.11'
        neutron_ports[1]['id'] = 'fake_port_id_1'
        neutron_ports[2]['fixed_ips'][0]['ip_address'] = '192.168.0.12'
        neutron_ports[2]['id'] = 'fake_port_id_2'
        neutron_ports[3]['fixed_ips'][0]['ip_address'] = '192.168.0.13'
        neutron_ports[3]['id'] = 'fake_port_id_3'

        self.mock_object(self.plugin, '_verify_share_network_subnet')
        self.mock_object(self.plugin, '_store_neutron_net_info')

        self.mock_object(self.plugin.neutron_api, 'list_ports',
                         mock.Mock(return_value=neutron_ports))

        return neutron_ports, allocations

    @ddt.data({}, exception.NotFound)
    def test_manage_network_allocations_create_update(self, side_effect):

        neutron_ports, allocations = self._setup_manage_network_allocations()

        self.mock_object(db_api, 'network_allocation_get',
                         mock.Mock(
                             side_effect=[exception.NotFound, side_effect,
                                          exception.NotFound, side_effect]))
        if side_effect:
            self.mock_object(db_api, 'network_allocation_create')
        else:
            self.mock_object(db_api, 'network_allocation_update')

        result = self.plugin.manage_network_allocations(
            self.fake_context, allocations, fake_share_server,
            share_network_subnet=fake_share_network_subnet)

        self.assertEqual(['fd12::2000'], result)

        self.plugin.neutron_api.list_ports.assert_called_once_with(
            network_id=fake_share_network_subnet['neutron_net_id'],
            device_owner='manila:share',
            fixed_ips='subnet_id=' +
                      fake_share_network_subnet['neutron_subnet_id'])

        db_api.network_allocation_get.assert_has_calls([
            mock.call(self.fake_context, 'fake_port_id_1', read_deleted=False),
            mock.call(self.fake_context, 'fake_port_id_1', read_deleted=True),
            mock.call(self.fake_context, 'fake_port_id_2', read_deleted=False),
            mock.call(self.fake_context, 'fake_port_id_2', read_deleted=True),
        ])

        port_dict_list = [{
            'share_server_id': fake_share_server['id'],
            'ip_address': x,
            'gateway': fake_share_network_subnet['gateway'],
            'mac_address': fake_neutron_port['mac_address'],
            'status': constants.STATUS_ACTIVE,
            'label': 'user',
            'network_type': fake_share_network_subnet['network_type'],
            'segmentation_id': fake_share_network_subnet['segmentation_id'],
            'ip_version': fake_share_network_subnet['ip_version'],
            'cidr': fake_share_network_subnet['cidr'],
            'mtu': fake_share_network_subnet['mtu'],
            'share_network_subnet_id': fake_share_network_subnet['id'],
        } for x in ['192.168.0.11', '192.168.0.12']]

        if side_effect:
            port_dict_list[0]['id'] = 'fake_port_id_1'
            port_dict_list[1]['id'] = 'fake_port_id_2'
            db_api.network_allocation_create.assert_has_calls([
                mock.call(self.fake_context, port_dict_list[0]),
                mock.call(self.fake_context, port_dict_list[1])
            ])
        else:
            for x in port_dict_list:
                x['deleted_at'] = None
                x['deleted'] = 'False'

            db_api.network_allocation_update.assert_has_calls([
                mock.call(self.fake_context, 'fake_port_id_1',
                          port_dict_list[0], read_deleted=True),
                mock.call(self.fake_context, 'fake_port_id_2',
                          port_dict_list[1], read_deleted=True)
            ])

        self.plugin._verify_share_network_subnet.assert_called_once_with(
            fake_share_server['id'], fake_share_network_subnet)

        self.plugin._store_neutron_net_info(
            self.fake_context, fake_share_network_subnet)

    def test__get_ports_respective_to_ips_multiple_fixed_ips(self):
        self.mock_object(plugin.LOG, 'warning')

        allocations = ['192.168.0.10', '192.168.0.11', '192.168.0.12']

        neutron_ports = [
            copy.deepcopy(fake_neutron_port), copy.deepcopy(fake_neutron_port),
        ]

        neutron_ports[0]['fixed_ips'][0]['ip_address'] = '192.168.0.10'
        neutron_ports[0]['id'] = 'fake_port_id_0'
        neutron_ports[0]['fixed_ips'].append({'ip_address': '192.168.0.11',
                                              'subnet_id': 'test_subnet_id'})
        neutron_ports[1]['fixed_ips'][0]['ip_address'] = '192.168.0.12'
        neutron_ports[1]['id'] = 'fake_port_id_2'

        expected = [{'port': neutron_ports[0], 'allocation': '192.168.0.10'},
                    {'port': neutron_ports[1], 'allocation': '192.168.0.12'}]

        result = self.plugin._get_ports_respective_to_ips(allocations,
                                                          neutron_ports)

        self.assertEqual(expected, result)

        self.assertIs(True, plugin.LOG.warning.called)

    def test_manage_network_allocations_exception(self):

        neutron_ports, allocations = self._setup_manage_network_allocations()

        fake_allocation = {
            'id': 'fake_port_id',
            'share_server_id': 'fake_server_id'
        }

        self.mock_object(db_api, 'network_allocation_get',
                         mock.Mock(return_value=fake_allocation))

        self.assertRaises(
            exception.ManageShareServerError,
            self.plugin.manage_network_allocations, self.fake_context,
            allocations, fake_share_server, fake_share_network,
            fake_share_network_subnet)

        db_api.network_allocation_get.assert_called_once_with(
            self.fake_context, 'fake_port_id_1', read_deleted=False)

    def test_unmanage_network_allocations(self):

        neutron_ports = [
            copy.deepcopy(fake_neutron_port), copy.deepcopy(fake_neutron_port),
        ]

        neutron_ports[0]['id'] = 'fake_port_id_0'
        neutron_ports[1]['id'] = 'fake_port_id_1'

        get_mock = self.mock_object(
            db_api, 'network_allocations_get_for_share_server',
            mock.Mock(return_value=neutron_ports))

        self.mock_object(db_api, 'network_allocation_delete')

        self.plugin.unmanage_network_allocations(
            self.fake_context, fake_share_server['id'])

        get_mock.assert_called_once_with(
            self.fake_context, fake_share_server['id'])

        db_api.network_allocation_delete.assert_has_calls([
            mock.call(self.fake_context, 'fake_port_id_0'),
            mock.call(self.fake_context, 'fake_port_id_1')
        ])

    @mock.patch.object(db_api, 'network_allocation_delete', mock.Mock())
    @mock.patch.object(db_api, 'share_network_update', mock.Mock())
    @mock.patch.object(db_api, 'network_allocations_get_for_share_server',
                       mock.Mock(return_value=[fake_network_allocation]))
    def test_deallocate_network_nominal(self):
        share_srv = {'id': fake_share_server['id']}
        share_srv['network_allocations'] = [fake_network_allocation]

        with mock.patch.object(self.plugin.neutron_api, 'delete_port',
                               mock.Mock()):
            self.plugin.deallocate_network(self.fake_context, share_srv)
            self.plugin.neutron_api.delete_port.assert_called_once_with(
                fake_network_allocation['id'])
            db_api.network_allocation_delete.assert_called_once_with(
                self.fake_context,
                fake_network_allocation['id'])

    @mock.patch.object(db_api, 'share_network_update',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'network_allocation_update', mock.Mock())
    @mock.patch.object(db_api, 'network_allocations_get_for_share_server',
                       mock.Mock(return_value=[fake_network_allocation]))
    def test_deallocate_network_neutron_api_exception(self):
        share_srv = {'id': fake_share_server['id']}
        share_srv['network_allocations'] = [fake_network_allocation]

        delete_port = mock.patch.object(self.plugin.neutron_api,
                                        'delete_port').start()
        delete_port.side_effect = exception.NetworkException

        self.assertRaises(exception.NetworkException,
                          self.plugin.deallocate_network,
                          self.fake_context,
                          share_srv)
        db_api.network_allocation_update.assert_called_once_with(
            self.fake_context,
            fake_network_allocation['id'],
            {'status': constants.STATUS_ERROR})
        delete_port.stop()

    @mock.patch.object(db_api, 'share_network_subnet_update', mock.Mock())
    def test_save_neutron_network_data(self):
        neutron_nw_info = {
            'provider:network_type': 'vlan',
            'provider:segmentation_id': 1000,
            'mtu': 1509,
        }
        share_nw_update_dict = {
            'network_type': 'vlan',
            'segmentation_id': 1000,
            'mtu': 1509,
        }

        with mock.patch.object(self.plugin.neutron_api,
                               'get_network',
                               mock.Mock(return_value=neutron_nw_info)):
            self.plugin._save_neutron_network_data(self.fake_context,
                                                   fake_share_network_subnet)

            self.plugin.neutron_api.get_network.assert_called_once_with(
                fake_share_network_subnet['neutron_net_id'])
            self.plugin.db.share_network_subnet_update.assert_called_once_with(
                self.fake_context,
                fake_share_network_subnet['id'],
                share_nw_update_dict)

    @mock.patch.object(db_api, 'share_network_subnet_update', mock.Mock())
    def test_save_neutron_network_data_multi_segment(self):
        share_nw_update_dict = {
            'network_type': 'vlan',
            'segmentation_id': 3926,
            'mtu': 1509
        }
        config_data = {
            'DEFAULT': {
                'neutron_physical_net_name': 'net1',
            }
        }

        self.mock_object(self.plugin.neutron_api, 'get_network')
        self.plugin.neutron_api.get_network.return_value = fake_nw_info

        with test_utils.create_temp_config_with_opts(config_data):
            self.plugin._save_neutron_network_data(self.fake_context,
                                                   fake_share_network_subnet)

        self.plugin.neutron_api.get_network.assert_called_once_with(
            fake_share_network_subnet['neutron_net_id'])
        self.plugin.db.share_network_subnet_update.assert_called_once_with(
            self.fake_context,
            fake_share_network_subnet['id'],
            share_nw_update_dict)

    @mock.patch.object(db_api, 'share_network_update', mock.Mock())
    def test_save_neutron_network_data_multi_segment_without_ident(self):
        config_data = {
            'DEFAULT': {
                'neutron_physical_net_name': 'net100',
            }
        }

        self.mock_object(self.plugin.neutron_api, 'get_network')
        self.plugin.neutron_api.get_network.return_value = fake_nw_info

        with test_utils.create_temp_config_with_opts(config_data):
            self.assertRaises(exception.NetworkBadConfigurationException,
                              self.plugin._save_neutron_network_data,
                              self.fake_context, fake_share_network_subnet)

    @mock.patch.object(db_api, 'share_network_update', mock.Mock())
    def test_save_neutron_network_data_multi_segment_without_cfg(self):
        self.mock_object(self.plugin.neutron_api, 'get_network')
        self.plugin.neutron_api.get_network.return_value = fake_nw_info

        self.assertRaises(exception.NetworkBadConfigurationException,
                          self.plugin._save_neutron_network_data,
                          self.fake_context, fake_share_network_subnet)

    @mock.patch.object(db_api, 'share_network_subnet_update', mock.Mock())
    def test_save_neutron_subnet_data(self):
        neutron_subnet_info = fake_neutron_subnet
        subnet_value = {
            'cidr': '10.0.0.0/24',
            'ip_version': 4,
            'gateway': '10.0.0.1',
        }

        with mock.patch.object(self.plugin.neutron_api,
                               'get_subnet',
                               mock.Mock(return_value=neutron_subnet_info)):
            self.plugin._save_neutron_subnet_data(self.fake_context,
                                                  fake_share_network_subnet)

            self.plugin.neutron_api.get_subnet.assert_called_once_with(
                fake_share_network_subnet['neutron_subnet_id'])
            self.plugin.db.share_network_subnet_update.assert_called_once_with(
                self.fake_context,
                fake_share_network_subnet['id'],
                subnet_value)

    def test_has_network_provider_extension_true(self):
        extensions = {neutron_constants.PROVIDER_NW_EXT: {}}
        with mock.patch.object(self.plugin.neutron_api,
                               'list_extensions',
                               mock.Mock(return_value=extensions)):
            result = self.plugin._has_provider_network_extension()

            self.plugin.neutron_api.list_extensions.assert_any_call()
            self.assertTrue(result)

    def test_has_network_provider_extension_false(self):
        with mock.patch.object(self.plugin.neutron_api,
                               'list_extensions',
                               mock.Mock(return_value={})):
            result = self.plugin._has_provider_network_extension()

            self.plugin.neutron_api.list_extensions.assert_any_call()
            self.assertFalse(result)


@ddt.ddt
class NeutronSingleNetworkPluginTest(test.TestCase):

    def setUp(self):
        super(NeutronSingleNetworkPluginTest, self).setUp()
        self.context = 'fake_context'

    def test_init_valid(self):
        fake_net_id = 'fake_net_id'
        fake_subnet_id = 'fake_subnet_id'
        config_data = {
            'DEFAULT': {
                'neutron_net_id': fake_net_id,
                'neutron_subnet_id': fake_subnet_id,
            }
        }
        fake_net = {'subnets': ['fake1', 'fake2', fake_subnet_id]}
        self.mock_object(
            neutron_api.API, 'get_network', mock.Mock(return_value=fake_net))

        with test_utils.create_temp_config_with_opts(config_data):
            instance = plugin.NeutronSingleNetworkPlugin()

            self.assertEqual(fake_net_id, instance.net)
            self.assertEqual(fake_subnet_id, instance.subnet)
            neutron_api.API.get_network.assert_called_once_with(fake_net_id)

    @ddt.data(
        {'net': None, 'subnet': None},
        {'net': 'fake_net_id', 'subnet': None},
        {'net': None, 'subnet': 'fake_subnet_id'})
    @ddt.unpack
    def test_init_invalid(self, net, subnet):
        config_data = dict()
        # Simulate absence of set values
        if net:
            config_data['neutron_net_id'] = net
        if subnet:
            config_data['neutron_subnet_id'] = subnet
        config_data = dict(DEFAULT=config_data)

        with test_utils.create_temp_config_with_opts(config_data):
            self.assertRaises(
                exception.NetworkBadConfigurationException,
                plugin.NeutronSingleNetworkPlugin)

    @ddt.data({}, {'subnets': []}, {'subnets': ['different_foo_subnet']})
    def test_init_subnet_does_not_belong_to_net(self, fake_net):
        fake_net_id = 'fake_net_id'
        config_data = {
            'DEFAULT': {
                'neutron_net_id': fake_net_id,
                'neutron_subnet_id': 'fake_subnet_id',
            }
        }
        self.mock_object(
            neutron_api.API, 'get_network', mock.Mock(return_value=fake_net))

        with test_utils.create_temp_config_with_opts(config_data):
            self.assertRaises(
                exception.NetworkBadConfigurationException,
                plugin.NeutronSingleNetworkPlugin)
            neutron_api.API.get_network.assert_called_once_with(fake_net_id)

    def _get_neutron_network_plugin_instance(
            self, config_data=None, label=None):
        if not config_data:
            fake_subnet_id = 'fake_subnet_id'
            config_data = {
                'DEFAULT': {
                    'neutron_net_id': 'fake_net_id',
                    'neutron_subnet_id': fake_subnet_id,
                }
            }
            fake_net = {'subnets': [fake_subnet_id]}
            self.mock_object(
                neutron_api.API, 'get_network',
                mock.Mock(return_value=fake_net))
        with test_utils.create_temp_config_with_opts(config_data):
            instance = plugin.NeutronSingleNetworkPlugin(label=label)
            return instance

    def test___update_share_network_net_data_same_values(self):
        instance = self._get_neutron_network_plugin_instance()
        share_network = {
            'neutron_net_id': instance.net,
            'neutron_subnet_id': instance.subnet,
        }

        result = instance._update_share_network_net_data(
            self.context, share_network)

        self.assertEqual(share_network, result)

    def test___update_share_network_net_data_different_values_empty(self):
        instance = self._get_neutron_network_plugin_instance()
        share_network_input = {
            'id': 'fake_share_network_id',
        }
        share_network_result = {
            'neutron_net_id': instance.net,
            'neutron_subnet_id': instance.subnet,
        }
        self.mock_object(
            instance.db, 'share_network_subnet_update',
            mock.Mock(return_value='foo'))

        instance._update_share_network_net_data(
            self.context, share_network_input)

        instance.db.share_network_subnet_update.assert_called_once_with(
            self.context, share_network_input['id'], share_network_result)

    @ddt.data(
        {'n': 'fake_net_id', 's': 'bar'},
        {'n': 'foo', 's': 'fake_subnet_id'})
    @ddt.unpack
    def test___update_share_network_net_data_different_values(self, n, s):
        instance = self._get_neutron_network_plugin_instance()
        share_network = {
            'id': 'fake_share_network_id',
            'neutron_net_id': n,
            'neutron_subnet_id': s,
        }
        self.mock_object(
            instance.db, 'share_network_update',
            mock.Mock(return_value=share_network))

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            instance._update_share_network_net_data,
            self.context, share_network)
        self.assertFalse(instance.db.share_network_update.called)

    def test_allocate_network(self):
        self.mock_object(plugin.NeutronNetworkPlugin, 'allocate_network')
        plugin.NeutronNetworkPlugin.allocate_network.return_value = [
            fake_neutron_port, fake_neutron_port]
        instance = self._get_neutron_network_plugin_instance()
        share_server = 'fake_share_server'
        share_network = {'id': 'fake_share_network'}
        share_network_subnet = {'id': 'fake_share_network_subnet'}
        share_network_subnet_upd = {'id': 'updated_fake_share_network_subnet'}
        count = 2
        device_owner = 'fake_device_owner'
        self.mock_object(
            instance, '_update_share_network_net_data',
            mock.Mock(return_value=share_network_subnet_upd))

        instance.allocate_network(
            self.context, share_server, share_network, share_network_subnet,
            count=count, device_owner=device_owner)

        instance._update_share_network_net_data.assert_called_once_with(
            self.context, share_network_subnet)
        plugin.NeutronNetworkPlugin.allocate_network.assert_called_once_with(
            self.context, share_server, share_network,
            share_network_subnet_upd, count=count, device_owner=device_owner)

    def test_manage_network_allocations(self):
        allocations = ['192.168.10.10', 'fd12::2000']
        instance = self._get_neutron_network_plugin_instance()
        parent = self.mock_object(
            plugin.NeutronNetworkPlugin, 'manage_network_allocations',
            mock.Mock(return_value=['fd12::2000']))
        self.mock_object(
            instance, '_update_share_network_net_data',
            mock.Mock(return_value=fake_share_network_subnet))

        result = instance.manage_network_allocations(
            self.context, allocations, fake_share_server, fake_share_network,
            fake_share_network_subnet)

        self.assertEqual(['fd12::2000'], result)

        instance._update_share_network_net_data.assert_called_once_with(
            self.context, fake_share_network_subnet)

        parent.assert_called_once_with(
            self.context, allocations, fake_share_server, fake_share_network,
            fake_share_network_subnet)

    def test_manage_network_allocations_admin(self):
        allocations = ['192.168.10.10', 'fd12::2000']
        instance = self._get_neutron_network_plugin_instance(label='admin')
        parent = self.mock_object(
            plugin.NeutronNetworkPlugin, 'manage_network_allocations',
            mock.Mock(return_value=['fd12::2000']))

        share_network_dict = {
            'project_id': instance.neutron_api.admin_project_id,
            'neutron_net_id': 'fake_net_id',
            'neutron_subnet_id': 'fake_subnet_id',
        }

        result = instance.manage_network_allocations(
            self.context, allocations, fake_share_server,
            share_network_subnet=share_network_dict)

        self.assertEqual(['fd12::2000'], result)

        parent.assert_called_once_with(
            self.context, allocations, fake_share_server, None,
            share_network_dict)


@ddt.ddt
class NeutronBindNetworkPluginTest(test.TestCase):
    def setUp(self):
        super(NeutronBindNetworkPluginTest, self).setUp()
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)
        self.has_binding_ext_mock = self.mock_object(
            neutron_api.API, '_has_port_binding_extension')
        self.has_binding_ext_mock.return_value = True
        self.bind_plugin = self._get_neutron_network_plugin_instance()
        self.bind_plugin.db = db_api
        self.sleep_mock = self.mock_object(time, 'sleep')
        self.fake_share_network_multi = dict(fake_share_network_multi)

    def _get_neutron_network_plugin_instance(self, config_data=None):
        if config_data is None:
            return plugin.NeutronBindNetworkPlugin()
        with test_utils.create_temp_config_with_opts(config_data):
            return plugin.NeutronBindNetworkPlugin()

    def test_wait_for_bind(self):
        self.mock_object(self.bind_plugin.neutron_api, 'show_port')
        self.bind_plugin.neutron_api.show_port.return_value = fake_neutron_port

        self.bind_plugin._wait_for_ports_bind([fake_neutron_port],
                                              fake_share_server)

        self.bind_plugin.neutron_api.show_port.assert_called_once_with(
            fake_neutron_port['id'])
        self.sleep_mock.assert_not_called()

    def test_wait_for_bind_error(self):
        fake_neut_port = copy.copy(fake_neutron_port)
        fake_neut_port['status'] = 'ERROR'
        self.mock_object(self.bind_plugin.neutron_api, 'show_port')
        self.bind_plugin.neutron_api.show_port.return_value = fake_neut_port

        self.assertRaises(exception.NetworkException,
                          self.bind_plugin._wait_for_ports_bind,
                          [fake_neut_port, fake_neut_port],
                          fake_share_server)

        self.bind_plugin.neutron_api.show_port.assert_called_once_with(
            fake_neutron_port['id'])
        self.sleep_mock.assert_not_called()

    @ddt.data(('DOWN', 'ACTIVE'), ('DOWN', 'DOWN'), ('ACTIVE', 'DOWN'))
    def test_wait_for_bind_two_ports_no_bind(self, state):
        fake_neut_port1 = copy.copy(fake_neutron_port)
        fake_neut_port1['status'] = state[0]
        fake_neut_port2 = copy.copy(fake_neutron_port)
        fake_neut_port2['status'] = state[1]
        self.mock_object(self.bind_plugin.neutron_api, 'show_port')
        self.bind_plugin.neutron_api.show_port.side_effect = (
            [fake_neut_port1, fake_neut_port2] * 20)

        self.assertRaises(exception.NetworkBindException,
                          self.bind_plugin._wait_for_ports_bind,
                          [fake_neut_port1, fake_neut_port2],
                          fake_share_server)

    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test_allocate_network_one_allocation(self):
        self.mock_object(self.bind_plugin, '_has_provider_network_extension')
        self.bind_plugin._has_provider_network_extension.return_value = True
        save_nw_data = self.mock_object(self.bind_plugin,
                                        '_save_neutron_network_data')
        save_subnet_data = self.mock_object(self.bind_plugin,
                                            '_save_neutron_subnet_data')
        self.mock_object(self.bind_plugin, '_wait_for_ports_bind')
        neutron_host_id_opts = plugin.neutron_bind_network_plugin_opts[1]
        self.mock_object(neutron_host_id_opts, 'default')
        neutron_host_id_opts.default = 'foohost1'
        self.mock_object(db_api, 'network_allocation_create')
        db_api.network_allocation_create.return_value = fake_network_allocation
        self.mock_object(self.bind_plugin.neutron_api, 'get_network')
        self.bind_plugin.neutron_api.get_network.return_value = (
            fake_neutron_network)

        with mock.patch.object(self.bind_plugin.neutron_api, 'create_port',
                               mock.Mock(return_value=fake_neutron_port)):
            self.bind_plugin.allocate_network(
                self.fake_context,
                fake_share_server,
                fake_share_network,
                fake_share_network_subnet,
                allocation_info={'count': 1})

            self.bind_plugin._has_provider_network_extension.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network_subnet,
                                                 save_db=True)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network_subnet,
                                                     save_db=True)
            expected_kwargs = {
                'binding:vnic_type': 'baremetal',
                'host_id': 'foohost1',
                'network_id': fake_share_network_subnet['neutron_net_id'],
                'subnet_id': fake_share_network_subnet['neutron_subnet_id'],
                'device_owner': 'manila:share',
                'device_id': fake_share_network['id'],
            }
            self.bind_plugin.neutron_api.create_port.assert_called_once_with(
                fake_share_network['project_id'], **expected_kwargs)
            db_api.network_allocation_create.assert_called_once_with(
                self.fake_context,
                fake_network_allocation)
            self.bind_plugin._wait_for_ports_bind.assert_called_once_with(
                [db_api.network_allocation_create(
                    self.fake_context, fake_network_allocation)],
                fake_share_server)

    @mock.patch.object(db_api, 'network_allocation_create',
                       mock.Mock(return_values=fake_network_allocation_multi))
    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network_multi))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test_allocate_network_multi_segment(self):
        network_allocation_update_data = {
            'network_type':
                fake_nw_info['segments'][0]['provider:network_type'],
            'segmentation_id':
                fake_nw_info['segments'][0]['provider:segmentation_id'],
        }
        network_update_data = dict(network_allocation_update_data)
        network_update_data['mtu'] = fake_nw_info['mtu']
        fake_network_allocation_multi_updated = dict(
            fake_network_allocation_multi)
        fake_network_allocation_multi_updated.update(
            network_allocation_update_data)
        fake_share_network_multi_updated = dict(fake_share_network_multi)
        fake_share_network_multi_updated.update(network_update_data)
        fake_share_network_multi_updated.update(fake_neutron_subnet)
        config_data = {
            'DEFAULT': {
                'neutron_net_id': 'fake net id',
                'neutron_subnet_id': 'fake subnet id',
                'neutron_physical_net_name': 'net1',
            }
        }
        self.bind_plugin = self._get_neutron_network_plugin_instance(
            config_data)
        self.bind_plugin.db = db_api

        self.mock_object(self.bind_plugin, '_has_provider_network_extension')
        self.bind_plugin._has_provider_network_extension.return_value = True
        self.mock_object(self.bind_plugin, '_wait_for_ports_bind')
        neutron_host_id_opts = plugin.neutron_bind_network_plugin_opts[1]
        self.mock_object(neutron_host_id_opts, 'default')
        neutron_host_id_opts.default = 'foohost1'

        self.mock_object(db_api, 'network_allocation_create')
        db_api.network_allocation_create.return_value = (
            fake_network_allocation_multi)
        self.mock_object(db_api, 'network_allocation_update')
        db_api.network_allocation_update.return_value = (
            fake_network_allocation_multi_updated)
        self.mock_object(self.bind_plugin.neutron_api, 'get_network')
        self.bind_plugin.neutron_api.get_network.return_value = (
            fake_neutron_network_multi)
        self.mock_object(self.bind_plugin.neutron_api, 'get_subnet')
        self.bind_plugin.neutron_api.get_subnet.return_value = (
            fake_neutron_subnet)
        self.mock_object(db_api, 'share_network_subnet_update')

        with mock.patch.object(self.bind_plugin.neutron_api, 'create_port',
                               mock.Mock(return_value=fake_neutron_port)):
            self.bind_plugin.allocate_network(
                self.fake_context,
                fake_share_server,
                fake_share_network,
                self.fake_share_network_multi,
                allocation_info={'count': 1})

            self.bind_plugin._has_provider_network_extension.assert_any_call()
            expected_kwargs = {
                'binding:vnic_type': 'baremetal',
                'host_id': 'foohost1',
                'network_id': fake_share_network_multi['neutron_net_id'],
                'subnet_id': fake_share_network_multi['neutron_subnet_id'],
                'device_owner': 'manila:share',
                'device_id': fake_share_network_multi['id']
            }
            self.bind_plugin.neutron_api.create_port.assert_called_once_with(
                fake_share_network_multi['project_id'], **expected_kwargs)
            db_api.network_allocation_create.assert_called_once_with(
                self.fake_context,
                fake_network_allocation_multi)
            db_api.share_network_subnet_update.assert_called_with(
                self.fake_context,
                fake_share_network_multi['id'],
                network_update_data)
            network_allocation_update_data['cidr'] = (
                fake_neutron_subnet['cidr'])
            network_allocation_update_data['ip_version'] = (
                fake_neutron_subnet['ip_version'])
            db_api.network_allocation_update.assert_called_once_with(
                self.fake_context,
                fake_neutron_port['id'],
                network_allocation_update_data)

    @ddt.data({
        'neutron_binding_profiles': None,
        'binding_profiles': {}
    }, {
        'neutron_binding_profiles': 'fake_profile',
        'binding_profiles': {}
    }, {
        'neutron_binding_profiles': 'fake_profile',
        'binding_profiles': None
    }, {
        'neutron_binding_profiles': 'fake_profile',
        'binding_profiles': {
            'fake_profile': {
                'neutron_switch_id': 'fake switch id',
                'neutron_port_id': 'fake port id',
                'neutron_switch_info': 'switch_ip: 127.0.0.1'
            }
        }
    }, {
        'neutron_binding_profiles': None,
        'binding_profiles': {
            'fake_profile': {
                'neutron_switch_id': 'fake switch id',
                'neutron_port_id': 'fake port id',
                'neutron_switch_info': 'switch_ip: 127.0.0.1'
            }
        }
    }, {
        'neutron_binding_profiles': 'fake_profile_one,fake_profile_two',
        'binding_profiles': {
            'fake_profile_one': {
                'neutron_switch_id': 'fake switch id 1',
                'neutron_port_id': 'fake port id 1',
                'neutron_switch_info': 'switch_ip: 127.0.0.1'
            },
            'fake_profile_two': {
                'neutron_switch_id': 'fake switch id 2',
                'neutron_port_id': 'fake port id 2',
                'neutron_switch_info': 'switch_ip: 127.0.0.2'
            }
        }
    }, {
        'neutron_binding_profiles': 'fake_profile_two',
        'binding_profiles': {
            'fake_profile_one': {
                'neutron_switch_id': 'fake switch id 1',
                'neutron_port_id': 'fake port id 1',
                'neutron_switch_info': 'switch_ip: 127.0.0.1'
            },
            'fake_profile_two': {
                'neutron_switch_id': 'fake switch id 2',
                'neutron_port_id': 'fake port id 2',
                'neutron_switch_info': 'switch_ip: 127.0.0.2'
            }
        }
    })
    @ddt.unpack
    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test__get_port_create_args(self, neutron_binding_profiles,
                                   binding_profiles):
        fake_device_owner = 'share'
        fake_host_id = 'fake host'
        neutron_host_id_opts = plugin.neutron_bind_network_plugin_opts[1]
        self.mock_object(neutron_host_id_opts, 'default')
        neutron_host_id_opts.default = fake_host_id

        config_data = {
            'DEFAULT': {
                'neutron_net_id': fake_neutron_network['id'],
                'neutron_subnet_id': fake_neutron_network['subnets'][0]
            }
        }
        # Simulate absence of set values
        if neutron_binding_profiles:
            config_data['DEFAULT'][
                'neutron_binding_profiles'] = neutron_binding_profiles
        if binding_profiles:
            for name, binding_profile in binding_profiles.items():
                config_data[name] = binding_profile

        instance = self._get_neutron_network_plugin_instance(config_data)

        create_args = instance._get_port_create_args(fake_share_server,
                                                     fake_share_network_subnet,
                                                     fake_device_owner)

        expected_create_args = {
            'binding:vnic_type': 'baremetal',
            'host_id': fake_host_id,
            'network_id': fake_share_network_subnet['neutron_net_id'],
            'subnet_id': fake_share_network_subnet['neutron_subnet_id'],
            'device_owner': 'manila:' + fake_device_owner,
            'device_id': fake_share_server['id']
        }
        if neutron_binding_profiles:
            expected_create_args['binding:profile'] = {
                'local_link_information': []
            }
            local_links = expected_create_args[
                'binding:profile']['local_link_information']
            for profile in neutron_binding_profiles.split(','):
                if binding_profiles is None:
                    binding_profile = {}
                else:
                    binding_profile = binding_profiles.get(profile, {})
                local_links.append({
                    'port_id': binding_profile.get('neutron_port_id', None),
                    'switch_id': binding_profile.get('neutron_switch_id', None)
                })
                switch_info = binding_profile.get('neutron_switch_info', None)
                if switch_info is None:
                    local_links[-1]['switch_info'] = None
                else:
                    local_links[-1]['switch_info'] = cfg.types.Dict()(
                        switch_info)

        self.assertEqual(expected_create_args, create_args)

    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test__get_port_create_args_host_id(self):
        fake_device_owner = 'share'
        fake_host_id = 'fake host'

        config_data = {
            'DEFAULT': {
                'neutron_net_id': fake_neutron_network['id'],
                'neutron_subnet_id': fake_neutron_network['subnets'][0],
                'neutron_host_id': fake_host_id
            }
        }

        instance = self._get_neutron_network_plugin_instance(config_data)

        create_args = instance._get_port_create_args(fake_share_server,
                                                     fake_share_network_subnet,
                                                     fake_device_owner)

        expected_create_args = {
            'binding:vnic_type': 'baremetal',
            'host_id': fake_host_id,
            'network_id': fake_share_network_subnet['neutron_net_id'],
            'subnet_id': fake_share_network_subnet['neutron_subnet_id'],
            'device_owner': 'manila:' + fake_device_owner,
            'device_id': fake_share_server['id']
        }

        self.assertEqual(expected_create_args, create_args)


@ddt.ddt
class NeutronBindSingleNetworkPluginTest(test.TestCase):
    def setUp(self):
        super(NeutronBindSingleNetworkPluginTest, self).setUp()
        self.context = 'fake_context'
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)
        self.has_binding_ext_mock = self.mock_object(
            neutron_api.API, '_has_port_binding_extension')
        self.has_binding_ext_mock.return_value = True
        self.bind_plugin = plugin.NeutronBindNetworkPlugin()
        self.bind_plugin.db = db_api
        self.sleep_mock = self.mock_object(time, 'sleep')
        self.bind_plugin = self._get_neutron_network_plugin_instance()
        self.bind_plugin.db = db_api

    def _get_neutron_network_plugin_instance(self, config_data=None):
        if not config_data:
            fake_net_id = 'fake net id'
            fake_subnet_id = 'fake subnet id'
            config_data = {
                'DEFAULT': {
                    'neutron_net_id': fake_net_id,
                    'neutron_subnet_id': fake_subnet_id,
                    'neutron_physical_net_name': 'net1',
                }
            }
            fake_net = {'subnets': ['fake1', 'fake2', fake_subnet_id]}
            self.mock_object(
                neutron_api.API, 'get_network',
                mock.Mock(return_value=fake_net))
        with test_utils.create_temp_config_with_opts(config_data):
            return plugin.NeutronBindSingleNetworkPlugin()

    def test_allocate_network(self):
        self.mock_object(plugin.NeutronNetworkPlugin, 'allocate_network')
        plugin.NeutronNetworkPlugin.allocate_network.return_value = [
            'port1', 'port2']
        instance = self._get_neutron_network_plugin_instance()
        share_server = 'fake_share_server'
        share_network = {}
        share_network_subnet = {'neutron_net_id': {}}
        share_network_upd = {'neutron_net_id': {'upd': True}}
        count = 2
        device_owner = 'fake_device_owner'
        self.mock_object(
            instance, '_update_share_network_net_data',
            mock.Mock(return_value=share_network_upd))
        self.mock_object(instance, '_wait_for_ports_bind', mock.Mock())

        instance.allocate_network(
            self.context, share_server, share_network, share_network_subnet,
            count=count, device_owner=device_owner)

        instance._update_share_network_net_data.assert_called_once_with(
            self.context, share_network_subnet)
        plugin.NeutronNetworkPlugin.allocate_network.assert_called_once_with(
            self.context, share_server, share_network, share_network_upd,
            count=count, device_owner=device_owner)
        instance._wait_for_ports_bind.assert_called_once_with(
            ['port1', 'port2'], share_server)

    def test_init_valid(self):
        fake_net_id = 'fake_net_id'
        fake_subnet_id = 'fake_subnet_id'
        config_data = {
            'DEFAULT': {
                'neutron_net_id': fake_net_id,
                'neutron_subnet_id': fake_subnet_id,
            }
        }
        fake_net = {'subnets': ['fake1', 'fake2', fake_subnet_id]}
        self.mock_object(
            neutron_api.API, 'get_network', mock.Mock(return_value=fake_net))

        with test_utils.create_temp_config_with_opts(config_data):
            instance = plugin.NeutronSingleNetworkPlugin()

            self.assertEqual(fake_net_id, instance.net)
            self.assertEqual(fake_subnet_id, instance.subnet)
            neutron_api.API.get_network.assert_called_once_with(fake_net_id)

    @ddt.data(
        {'net': None, 'subnet': None},
        {'net': 'fake_net_id', 'subnet': None},
        {'net': None, 'subnet': 'fake_subnet_id'})
    @ddt.unpack
    def test_init_invalid(self, net, subnet):
        config_data = dict()
        # Simulate absence of set values
        if net:
            config_data['neutron_net_id'] = net
        if subnet:
            config_data['neutron_subnet_id'] = subnet
        config_data = dict(DEFAULT=config_data)

        with test_utils.create_temp_config_with_opts(config_data):
            self.assertRaises(
                exception.NetworkBadConfigurationException,
                plugin.NeutronSingleNetworkPlugin)

    @ddt.data({}, {'subnets': []}, {'subnets': ['different_foo_subnet']})
    def test_init_subnet_does_not_belong_to_net(self, fake_net):
        fake_net_id = 'fake_net_id'
        config_data = {
            'DEFAULT': {
                'neutron_net_id': fake_net_id,
                'neutron_subnet_id': 'fake_subnet_id',
            }
        }
        self.mock_object(
            neutron_api.API, 'get_network', mock.Mock(return_value=fake_net))

        with test_utils.create_temp_config_with_opts(config_data):
            self.assertRaises(
                exception.NetworkBadConfigurationException,
                plugin.NeutronSingleNetworkPlugin)
            neutron_api.API.get_network.assert_called_once_with(fake_net_id)

    def _get_neutron_single_network_plugin_instance(self):
        fake_subnet_id = 'fake_subnet_id'
        config_data = {
            'DEFAULT': {
                'neutron_net_id': 'fake_net_id',
                'neutron_subnet_id': fake_subnet_id,
            }
        }
        fake_net = {'subnets': [fake_subnet_id]}
        self.mock_object(
            neutron_api.API, 'get_network', mock.Mock(return_value=fake_net))
        with test_utils.create_temp_config_with_opts(config_data):
            instance = plugin.NeutronSingleNetworkPlugin()
            return instance

    def test___update_share_network_net_data_same_values(self):
        instance = self._get_neutron_single_network_plugin_instance()
        share_network = {
            'neutron_net_id': instance.net,
            'neutron_subnet_id': instance.subnet,
        }

        result = instance._update_share_network_net_data(
            self.context, share_network)

        self.assertEqual(share_network, result)

    def test___update_share_network_net_data_different_values_empty(self):
        instance = self._get_neutron_single_network_plugin_instance()
        share_network_subnet_input = {
            'id': 'fake_share_network_id',
        }
        share_network_result = {
            'neutron_net_id': instance.net,
            'neutron_subnet_id': instance.subnet,
        }
        self.mock_object(
            instance.db, 'share_network_subnet_update',
            mock.Mock(return_value='foo'))

        instance._update_share_network_net_data(
            self.context, share_network_subnet_input)

        instance.db.share_network_subnet_update.assert_called_once_with(
            self.context, share_network_subnet_input['id'],
            share_network_result)

    @ddt.data(
        {'n': 'fake_net_id', 's': 'bar'},
        {'n': 'foo', 's': 'fake_subnet_id'})
    @ddt.unpack
    def test___update_share_network_net_data_different_values(self, n, s):
        instance = self._get_neutron_single_network_plugin_instance()
        share_network = {
            'id': 'fake_share_network_id',
            'neutron_net_id': n,
            'neutron_subnet_id': s,
        }
        self.mock_object(
            instance.db, 'share_network_update',
            mock.Mock(return_value=share_network))

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            instance._update_share_network_net_data,
            self.context, share_network)
        self.assertFalse(instance.db.share_network_update.called)

    def test_wait_for_bind(self):
        self.mock_object(self.bind_plugin.neutron_api, 'show_port')
        self.bind_plugin.neutron_api.show_port.return_value = fake_neutron_port

        self.bind_plugin._wait_for_ports_bind([fake_neutron_port],
                                              fake_share_server)

        self.bind_plugin.neutron_api.show_port.assert_called_once_with(
            fake_neutron_port['id'])
        self.sleep_mock.assert_not_called()

    def test_wait_for_bind_error(self):
        fake_neut_port = copy.copy(fake_neutron_port)
        fake_neut_port['status'] = 'ERROR'
        self.mock_object(self.bind_plugin.neutron_api, 'show_port')
        self.bind_plugin.neutron_api.show_port.return_value = fake_neut_port

        self.assertRaises(exception.NetworkException,
                          self.bind_plugin._wait_for_ports_bind,
                          [fake_neut_port, fake_neut_port],
                          fake_share_server)

        self.bind_plugin.neutron_api.show_port.assert_called_once_with(
            fake_neutron_port['id'])
        self.sleep_mock.assert_not_called()

    @ddt.data(('DOWN', 'ACTIVE'), ('DOWN', 'DOWN'), ('ACTIVE', 'DOWN'))
    def test_wait_for_bind_two_ports_no_bind(self, state):
        fake_neut_port1 = copy.copy(fake_neutron_port)
        fake_neut_port1['status'] = state[0]
        fake_neut_port2 = copy.copy(fake_neutron_port)
        fake_neut_port2['status'] = state[1]
        self.mock_object(self.bind_plugin.neutron_api, 'show_port')
        self.bind_plugin.neutron_api.show_port.side_effect = (
            [fake_neut_port1, fake_neut_port2] * 20)

        self.assertRaises(exception.NetworkBindException,
                          self.bind_plugin._wait_for_ports_bind,
                          [fake_neut_port1, fake_neut_port2],
                          fake_share_server)

    @mock.patch.object(db_api, 'network_allocation_create',
                       mock.Mock(return_values=fake_network_allocation))
    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test_allocate_network_one_allocation(self):
        self.mock_object(self.bind_plugin, '_has_provider_network_extension')
        self.bind_plugin._has_provider_network_extension.return_value = True
        save_nw_data = self.mock_object(self.bind_plugin,
                                        '_save_neutron_network_data')
        save_subnet_data = self.mock_object(self.bind_plugin,
                                            '_save_neutron_subnet_data')
        self.mock_object(self.bind_plugin, '_wait_for_ports_bind')
        neutron_host_id_opts = plugin.neutron_bind_network_plugin_opts[1]
        self.mock_object(neutron_host_id_opts, 'default')
        neutron_host_id_opts.default = 'foohost1'
        self.mock_object(db_api, 'network_allocation_create')

        with mock.patch.object(self.bind_plugin.neutron_api, 'create_port',
                               mock.Mock(return_value=fake_neutron_port)):
            self.bind_plugin.allocate_network(
                self.fake_context,
                fake_share_server,
                fake_share_network,
                fake_share_network_subnet,
                allocation_info={'count': 1})

            self.bind_plugin._has_provider_network_extension.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network_subnet,
                                                 save_db=True)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network_subnet,
                                                     save_db=True)
            expected_kwargs = {
                'binding:vnic_type': 'baremetal',
                'host_id': 'foohost1',
                'network_id': fake_share_network_subnet['neutron_net_id'],
                'subnet_id': fake_share_network_subnet['neutron_subnet_id'],
                'device_owner': 'manila:share',
                'device_id': fake_share_network['id'],
            }
            self.bind_plugin.neutron_api.create_port.assert_called_once_with(
                fake_share_network['project_id'], **expected_kwargs)
            db_api.network_allocation_create.assert_called_once_with(
                self.fake_context,
                fake_network_allocation)
            self.bind_plugin._wait_for_ports_bind.assert_called_once_with(
                [db_api.network_allocation_create(
                    self.fake_context, fake_network_allocation)],
                fake_share_server)

    @ddt.data({
        'neutron_binding_profiles': None,
        'binding_profiles': {}
    }, {
        'neutron_binding_profiles': 'fake_profile',
        'binding_profiles': {}
    }, {
        'neutron_binding_profiles': 'fake_profile',
        'binding_profiles': None
    }, {
        'neutron_binding_profiles': 'fake_profile',
        'binding_profiles': {
            'fake_profile': {
                'neutron_switch_id': 'fake switch id',
                'neutron_port_id': 'fake port id',
                'neutron_switch_info': 'switch_ip: 127.0.0.1'
            }
        }
    }, {
        'neutron_binding_profiles': None,
        'binding_profiles': {
            'fake_profile': {
                'neutron_switch_id': 'fake switch id',
                'neutron_port_id': 'fake port id',
                'neutron_switch_info': 'switch_ip: 127.0.0.1'
            }
        }
    }, {
        'neutron_binding_profiles': 'fake_profile_one,fake_profile_two',
        'binding_profiles': {
            'fake_profile_one': {
                'neutron_switch_id': 'fake switch id 1',
                'neutron_port_id': 'fake port id 1',
                'neutron_switch_info': 'switch_ip: 127.0.0.1'
            },
            'fake_profile_two': {
                'neutron_switch_id': 'fake switch id 2',
                'neutron_port_id': 'fake port id 2',
                'neutron_switch_info': 'switch_ip: 127.0.0.2'
            }
        }
    }, {
        'neutron_binding_profiles': 'fake_profile_two',
        'binding_profiles': {
            'fake_profile_one': {
                'neutron_switch_id': 'fake switch id 1',
                'neutron_port_id': 'fake port id 1',
                'neutron_switch_info': 'switch_ip: 127.0.0.1'
            },
            'fake_profile_two': {
                'neutron_switch_id': 'fake switch id 2',
                'neutron_port_id': 'fake port id 2',
                'neutron_switch_info': 'switch_ip: 127.0.0.2'
            }
        }
    })
    @ddt.unpack
    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test__get_port_create_args(self, neutron_binding_profiles,
                                   binding_profiles):
        fake_device_owner = 'share'
        fake_host_id = 'fake host'
        neutron_host_id_opts = plugin.neutron_bind_network_plugin_opts[1]
        self.mock_object(neutron_host_id_opts, 'default')
        neutron_host_id_opts.default = fake_host_id

        config_data = {
            'DEFAULT': {
                'neutron_net_id': fake_neutron_network['id'],
                'neutron_subnet_id': fake_neutron_network['subnets'][0]
            }
        }
        # Simulate absence of set values
        if neutron_binding_profiles:
            config_data['DEFAULT'][
                'neutron_binding_profiles'] = neutron_binding_profiles
        if binding_profiles:
            for name, binding_profile in binding_profiles.items():
                config_data[name] = binding_profile

        instance = self._get_neutron_network_plugin_instance(config_data)

        create_args = instance._get_port_create_args(fake_share_server,
                                                     fake_share_network_subnet,
                                                     fake_device_owner)

        expected_create_args = {
            'binding:vnic_type': 'baremetal',
            'host_id': fake_host_id,
            'network_id': fake_share_network_subnet['neutron_net_id'],
            'subnet_id': fake_share_network_subnet['neutron_subnet_id'],
            'device_owner': 'manila:' + fake_device_owner,
            'device_id': fake_share_server['id']
        }
        if neutron_binding_profiles:
            expected_create_args['binding:profile'] = {
                'local_link_information': []
            }
            local_links = expected_create_args[
                'binding:profile']['local_link_information']
            for profile in neutron_binding_profiles.split(','):
                if binding_profiles is None:
                    binding_profile = {}
                else:
                    binding_profile = binding_profiles.get(profile, {})
                local_links.append({
                    'port_id': binding_profile.get('neutron_port_id', None),
                    'switch_id': binding_profile.get('neutron_switch_id', None)
                })
                switch_info = binding_profile.get('neutron_switch_info', None)
                if switch_info is None:
                    local_links[-1]['switch_info'] = None
                else:
                    local_links[-1]['switch_info'] = cfg.types.Dict()(
                        switch_info)

        self.assertEqual(expected_create_args, create_args)

    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test__get_port_create_args_host_id(self):
        fake_device_owner = 'share'
        fake_host_id = 'fake host'

        config_data = {
            'DEFAULT': {
                'neutron_net_id': fake_neutron_network['id'],
                'neutron_subnet_id': fake_neutron_network['subnets'][0],
                'neutron_host_id': fake_host_id
            }
        }

        instance = self._get_neutron_network_plugin_instance(config_data)

        create_args = instance._get_port_create_args(fake_share_server,
                                                     fake_share_network_subnet,
                                                     fake_device_owner)

        expected_create_args = {
            'binding:vnic_type': 'baremetal',
            'host_id': fake_host_id,
            'network_id': fake_share_network_subnet['neutron_net_id'],
            'subnet_id': fake_share_network_subnet['neutron_subnet_id'],
            'device_owner': 'manila:' + fake_device_owner,
            'device_id': fake_share_server['id']
        }

        self.assertEqual(expected_create_args, create_args)


class NeutronBindNetworkPluginWithNormalTypeTest(test.TestCase):
    def setUp(self):
        super(NeutronBindNetworkPluginWithNormalTypeTest, self).setUp()
        config_data = {
            'DEFAULT': {
                'neutron_vnic_type': 'normal',
            }
        }
        self.plugin = plugin.NeutronNetworkPlugin()
        self.plugin.db = db_api
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)

        with test_utils.create_temp_config_with_opts(config_data):
            self.bind_plugin = plugin.NeutronBindNetworkPlugin()
            self.bind_plugin.db = db_api

    @mock.patch.object(db_api, 'network_allocation_create',
                       mock.Mock(return_values=fake_network_allocation))
    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test_allocate_network_one_allocation(self):
        self.mock_object(self.bind_plugin, '_has_provider_network_extension')
        self.bind_plugin._has_provider_network_extension.return_value = True
        save_nw_data = self.mock_object(self.bind_plugin,
                                        '_save_neutron_network_data')
        save_subnet_data = self.mock_object(self.bind_plugin,
                                            '_save_neutron_subnet_data')
        self.mock_object(self.bind_plugin, '_wait_for_ports_bind')
        neutron_host_id_opts = plugin.neutron_bind_network_plugin_opts[1]
        self.mock_object(neutron_host_id_opts, 'default')
        neutron_host_id_opts.default = 'foohost1'
        self.mock_object(db_api, 'network_allocation_create')
        multi_seg = self.mock_object(
            self.bind_plugin, '_is_neutron_multi_segment')
        multi_seg.return_value = False

        with mock.patch.object(self.bind_plugin.neutron_api, 'create_port',
                               mock.Mock(return_value=fake_neutron_port)):
            self.bind_plugin.allocate_network(
                self.fake_context,
                fake_share_server,
                fake_share_network,
                fake_share_network_subnet,
                allocation_info={'count': 1})

            self.bind_plugin._has_provider_network_extension.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network_subnet,
                                                 save_db=True)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network_subnet,
                                                     save_db=True)
            expected_kwargs = {
                'binding:vnic_type': 'normal',
                'host_id': 'foohost1',
                'network_id': fake_share_network_subnet['neutron_net_id'],
                'subnet_id': fake_share_network_subnet['neutron_subnet_id'],
                'device_owner': 'manila:share',
                'device_id': fake_share_server['id'],
            }
            self.bind_plugin.neutron_api.create_port.assert_called_once_with(
                fake_share_network['project_id'], **expected_kwargs)
            db_api.network_allocation_create.assert_called_once_with(
                self.fake_context,
                fake_network_allocation)
            self.bind_plugin._wait_for_ports_bind.assert_not_called()

    def test_update_network_allocation(self):
        self.mock_object(self.bind_plugin, '_wait_for_ports_bind')
        self.mock_object(db_api, 'network_allocations_get_for_share_server')
        db_api.network_allocations_get_for_share_server.return_value = [
            fake_neutron_port]

        self.bind_plugin.update_network_allocation(self.fake_context,
                                                   fake_share_server)

        self.bind_plugin._wait_for_ports_bind.assert_called_once_with(
            [fake_neutron_port], fake_share_server)


@ddt.ddt
class NeutronBindSingleNetworkPluginWithNormalTypeTest(test.TestCase):
    def setUp(self):
        super(NeutronBindSingleNetworkPluginWithNormalTypeTest, self).setUp()
        fake_net_id = 'fake net id'
        fake_subnet_id = 'fake subnet id'
        config_data = {
            'DEFAULT': {
                'neutron_net_id': fake_net_id,
                'neutron_subnet_id': fake_subnet_id,
                'neutron_vnic_type': 'normal',
            }
        }
        fake_net = {'subnets': ['fake1', 'fake2', fake_subnet_id]}
        self.mock_object(
            neutron_api.API, 'get_network', mock.Mock(return_value=fake_net))
        self.plugin = plugin.NeutronNetworkPlugin()
        self.plugin.db = db_api
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)

        with test_utils.create_temp_config_with_opts(config_data):
            self.bind_plugin = plugin.NeutronBindSingleNetworkPlugin()
            self.bind_plugin.db = db_api

    @mock.patch.object(db_api, 'network_allocation_create',
                       mock.Mock(return_values=fake_network_allocation))
    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'share_server_get',
                       mock.Mock(return_value=fake_share_server))
    def test_allocate_network_one_allocation(self):
        self.mock_object(self.bind_plugin, '_has_provider_network_extension')
        self.bind_plugin._has_provider_network_extension.return_value = True
        save_nw_data = self.mock_object(self.bind_plugin,
                                        '_save_neutron_network_data')
        save_subnet_data = self.mock_object(self.bind_plugin,
                                            '_save_neutron_subnet_data')
        self.mock_object(self.bind_plugin, '_wait_for_ports_bind')
        neutron_host_id_opts = plugin.neutron_bind_network_plugin_opts[1]
        self.mock_object(neutron_host_id_opts, 'default')
        neutron_host_id_opts.default = 'foohost1'
        self.mock_object(db_api, 'network_allocation_create')

        with mock.patch.object(self.bind_plugin.neutron_api, 'create_port',
                               mock.Mock(return_value=fake_neutron_port)):
            self.bind_plugin.allocate_network(
                self.fake_context,
                fake_share_server,
                fake_share_network,
                fake_share_network_subnet,
                allocation_info={'count': 1})

            self.bind_plugin._has_provider_network_extension.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network_subnet,
                                                 save_db=True)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network_subnet,
                                                     save_db=True)
            expected_kwargs = {
                'binding:vnic_type': 'normal',
                'host_id': 'foohost1',
                'network_id': fake_share_network_subnet['neutron_net_id'],
                'subnet_id': fake_share_network_subnet['neutron_subnet_id'],
                'device_owner': 'manila:share',
                'device_id': fake_share_network['id'],
            }
            self.bind_plugin.neutron_api.create_port.assert_called_once_with(
                fake_share_network['project_id'], **expected_kwargs)
            db_api.network_allocation_create.assert_called_once_with(
                self.fake_context,
                fake_network_allocation)
            self.bind_plugin._wait_for_ports_bind.assert_not_called()

    def test_update_network_allocation(self):
        self.mock_object(self.bind_plugin, '_wait_for_ports_bind')
        self.mock_object(db_api, 'network_allocations_get_for_share_server')
        db_api.network_allocations_get_for_share_server.return_value = [
            fake_neutron_port]

        self.bind_plugin.update_network_allocation(self.fake_context,
                                                   fake_share_server)

        self.bind_plugin._wait_for_ports_bind.assert_called_once_with(
            [fake_neutron_port], fake_share_server)

    @ddt.data({'fix_ips': [{'ip_address': 'test_ip'},
                           {'ip_address': '10.78.223.129'}],
               'ip_version': 4},
              {'fix_ips': [{'ip_address': 'test_ip'},
                           {'ip_address': 'ad80::abaa:0:c2:2'}],
               'ip_version': 6},
              {'fix_ips': [{'ip_address': '10.78.223.129'},
                           {'ip_address': 'ad80::abaa:0:c2:2'}],
               'ip_version': 6},
              )
    @ddt.unpack
    def test__get_matched_ip_address(self, fix_ips, ip_version):
        result = self.bind_plugin._get_matched_ip_address(fix_ips, ip_version)
        self.assertEqual(fix_ips[1]['ip_address'], result)

    @ddt.data({'fix_ips': [{'ip_address': 'test_ip_1'},
                           {'ip_address': 'test_ip_2'}],
               'ip_version': (4, 6)},
              {'fix_ips': [{'ip_address': 'ad80::abaa:0:c2:1'},
                           {'ip_address': 'ad80::abaa:0:c2:2'}],
               'ip_version': (4, )},
              {'fix_ips': [{'ip_address': '192.0.0.2'},
                           {'ip_address': '192.0.0.3'}],
               'ip_version': (6, )},
              {'fix_ips': [{'ip_address': '192.0.0.2/12'},
                           {'ip_address': '192.0.0.330'},
                           {'ip_address': 'ad80::001::ad80'},
                           {'ip_address': 'ad80::abaa:0:c2:2/64'}],
               'ip_version': (4, 6)},
              )
    @ddt.unpack
    def test__get_matched_ip_address_illegal(self, fix_ips, ip_version):
        for version in ip_version:
            self.assertRaises(exception.NetworkBadConfigurationException,
                              self.bind_plugin._get_matched_ip_address,
                              fix_ips, version)

    def _setup_include_network_info(self):
        data = {
            'DEFAULT': {
                'neutron_net_id': 'fake net id',
                'neutron_subnet_id': 'fake subnet id',
                'neutron_physical_net_name': 'net1',
            }
        }
        with test_utils.create_temp_config_with_opts(data):
            instance = plugin.NeutronNetworkPlugin()

        return instance

    def test_include_network_info(self):
        instance = self._setup_include_network_info()
        self.mock_object(instance, '_store_neutron_net_info')
        instance.include_network_info(fake_share_network)
        instance._store_neutron_net_info.assert_called_once_with(
            None, fake_share_network, save_db=False)
