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
import ddt
import mock
import time

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
        {"subnet_id": "test_subnet_id", "ip_address": "test_ip"},
    ],
    "id": "test_port_id",
    "security_groups": ["fake_sec_group_id"],
    "device_id": "fake_device_id",
}

fake_share_network = {
    'id': 'fake nw info id',
    'neutron_subnet_id': 'fake subnet id',
    'neutron_net_id': 'fake net id',
    'project_id': 'fake project id',
    'status': 'test_subnet_status',
    'name': 'fake name',
    'description': 'fake description',
    'security_services': [],
    'network_type': 'fake_network_type',
    'segmentation_id': 1234,
    'ip_version': 4,
    'cidr': 'fake_cidr',
    'gateway': 'fake_gateway',
    'mtu': 1509,
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
    'network_type': fake_share_network['network_type'],
    'segmentation_id': fake_share_network['segmentation_id'],
    'ip_version': fake_share_network['ip_version'],
    'cidr': fake_share_network['cidr'],
    'gateway': fake_share_network['gateway'],
    'mtu': 1509,
}


class NeutronNetworkPluginTest(test.TestCase):

    def setUp(self):
        super(NeutronNetworkPluginTest, self).setUp()
        self.plugin = plugin.NeutronNetworkPlugin()
        self.plugin.db = db_api
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)

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
                allocation_info={'count': 1})

            has_provider_nw_ext.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network)
            self.plugin.neutron_api.create_port.assert_called_once_with(
                fake_share_network['project_id'],
                network_id=fake_share_network['neutron_net_id'],
                subnet_id=fake_share_network['neutron_subnet_id'],
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
                self.fake_context,
                fake_share_server,
                fake_share_network,
                count=2)

            neutron_api_calls = [
                mock.call(fake_share_network['project_id'],
                          network_id=fake_share_network['neutron_net_id'],
                          subnet_id=fake_share_network['neutron_subnet_id'],
                          device_owner='manila:share',
                          device_id=fake_share_network['id']),
                mock.call(fake_share_network['project_id'],
                          network_id=fake_share_network['neutron_net_id'],
                          subnet_id=fake_share_network['neutron_subnet_id'],
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

    @mock.patch.object(db_api, 'share_network_update', mock.Mock())
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
                                                   fake_share_network)

            self.plugin.neutron_api.get_network.assert_called_once_with(
                fake_share_network['neutron_net_id'])
            self.plugin.db.share_network_update.assert_called_once_with(
                self.fake_context,
                fake_share_network['id'],
                share_nw_update_dict)

    @mock.patch.object(db_api, 'share_network_update', mock.Mock())
    def test_save_neutron_subnet_data(self):
        neutron_subnet_info = {
            'cidr': '10.0.0.0/24',
            'ip_version': 4,
            'gateway_ip': '10.0.0.1',
        }
        subnet_value = {
            'cidr': '10.0.0.0/24',
            'ip_version': 4,
            'gateway': '10.0.0.1',
        }

        with mock.patch.object(self.plugin.neutron_api,
                               'get_subnet',
                               mock.Mock(return_value=neutron_subnet_info)):
            self.plugin._save_neutron_subnet_data(self.fake_context,
                                                  fake_share_network)

            self.plugin.neutron_api.get_subnet.assert_called_once_with(
                fake_share_network['neutron_subnet_id'])
            self.plugin.db.share_network_update.assert_called_once_with(
                self.fake_context,
                fake_share_network['id'],
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
        share_network_input = {
            'id': 'fake_share_network_id',
        }
        share_network_result = {
            'neutron_net_id': instance.net,
            'neutron_subnet_id': instance.subnet,
        }
        self.mock_object(
            instance.db, 'share_network_update',
            mock.Mock(return_value='foo'))

        instance._update_share_network_net_data(
            self.context, share_network_input)

        instance.db.share_network_update.assert_called_once_with(
            self.context, share_network_input['id'], share_network_result)

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

    def test___update_share_network_net_data_nova_net_id_present(self):
        instance = self._get_neutron_single_network_plugin_instance()
        share_network = {
            'id': 'fake_share_network_id',
            'nova_net_id': 'foo',
        }
        self.mock_object(
            instance.db, 'share_network_update',
            mock.Mock(return_value=share_network))

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            instance._update_share_network_net_data,
            self.context, share_network)
        self.assertFalse(instance.db.share_network_update.called)

    @mock.patch.object(
        plugin.NeutronNetworkPlugin, "allocate_network", mock.Mock())
    def test_allocate_network(self):
        instance = self._get_neutron_single_network_plugin_instance()
        share_server = 'fake_share_server'
        share_network = 'fake_share_network'
        share_network_upd = 'updated_fake_share_network'
        count = 2
        device_owner = 'fake_device_owner'
        self.mock_object(
            instance, '_update_share_network_net_data',
            mock.Mock(return_value=share_network_upd))

        instance.allocate_network(
            self.context, share_server, share_network, count=count,
            device_owner=device_owner)

        instance._update_share_network_net_data.assert_called_once_with(
            self.context, share_network)
        plugin.NeutronNetworkPlugin.allocate_network.assert_called_once_with(
            self.context, share_server, share_network_upd, count=count,
            device_owner=device_owner)
        plugin.NeutronNetworkPlugin.allocate_network.reset_mock()


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
        self.bind_plugin = plugin.NeutronBindNetworkPlugin()
        self.bind_plugin.db = db_api
        self.sleep_mock = self.mock_object(time, 'sleep')

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

        self.assertRaises(exception.ManilaException,
                          self.bind_plugin._wait_for_ports_bind,
                          [fake_neut_port, fake_neut_port],
                          fake_share_server)

        self.bind_plugin.neutron_api.show_port.assert_called_once_with(
            fake_neutron_port['id'])
        self.sleep_mock.assert_not_called()

    @ddt.data(('DOWN', 'ACTIVE'), ('DOWN', 'DOWN'), ('ACTIVE', 'DOWN'))
    @mock.patch.object(time, 'time', side_effect=[1, 1, 3])
    def test_wait_for_bind_two_ports_no_bind(self, state, time_mock):
        fake_neut_port1 = copy.copy(fake_neutron_port)
        fake_neut_port1['status'] = state[0]
        fake_neut_port2 = copy.copy(fake_neutron_port)
        fake_neut_port2['status'] = state[1]
        self.mock_object(self.bind_plugin.neutron_api, 'show_port')
        self.bind_plugin.neutron_api.show_port.side_effect = [fake_neut_port1,
                                                              fake_neut_port2]

        self.assertRaises(exception.ManilaException,
                          self.bind_plugin._wait_for_ports_bind.__wrapped__,
                          self.bind_plugin,
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
                allocation_info={'count': 1})

            self.bind_plugin._has_provider_network_extension.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network)
            expected_kwargs = {
                'binding:vnic_type': 'baremetal',
                'host_id': 'foohost1',
                'network_id': fake_share_network['neutron_net_id'],
                'subnet_id': fake_share_network['neutron_subnet_id'],
                'device_owner': 'manila:share',
                'device_id': fake_share_network['id'],
            }
            self.bind_plugin.neutron_api.create_port.assert_called_once_with(
                fake_share_network['project_id'], **expected_kwargs)
            db_api.network_allocation_create.assert_called_once_with(
                self.fake_context,
                fake_network_allocation)
            self.bind_plugin._wait_for_ports_bind.assert_called_once_with(
                [db_api.network_allocation_create()], fake_share_server)


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
        fake_net_id = 'fake net id'
        fake_subnet_id = 'fake subnet id'
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
            self.bind_plugin = plugin.NeutronBindSingleNetworkPlugin()
            self.bind_plugin.db = db_api

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
        share_network_input = {
            'id': 'fake_share_network_id',
        }
        share_network_result = {
            'neutron_net_id': instance.net,
            'neutron_subnet_id': instance.subnet,
        }
        self.mock_object(
            instance.db, 'share_network_update',
            mock.Mock(return_value='foo'))

        instance._update_share_network_net_data(
            self.context, share_network_input)

        instance.db.share_network_update.assert_called_once_with(
            self.context, share_network_input['id'], share_network_result)

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

    def test___update_share_network_net_data_nova_net_id_present(self):
        instance = self._get_neutron_single_network_plugin_instance()
        share_network = {
            'id': 'fake_share_network_id',
            'nova_net_id': 'foo',
        }
        self.mock_object(
            instance.db, 'share_network_update',
            mock.Mock(return_value=share_network))

        self.assertRaises(
            exception.NetworkBadConfigurationException,
            instance._update_share_network_net_data,
            self.context, share_network)
        self.assertFalse(instance.db.share_network_update.called)

    @mock.patch.object(
        plugin.NeutronNetworkPlugin, "allocate_network", mock.Mock())
    def test_allocate_network(self):
        instance = self._get_neutron_single_network_plugin_instance()
        share_server = 'fake_share_server'
        share_network = 'fake_share_network'
        share_network_upd = 'updated_fake_share_network'
        count = 2
        device_owner = 'fake_device_owner'
        self.mock_object(
            instance, '_update_share_network_net_data',
            mock.Mock(return_value=share_network_upd))

        instance.allocate_network(
            self.context, share_server, share_network, count=count,
            device_owner=device_owner)

        instance._update_share_network_net_data.assert_called_once_with(
            self.context, share_network)
        plugin.NeutronNetworkPlugin.allocate_network.assert_called_once_with(
            self.context, share_server, share_network_upd, count=count,
            device_owner=device_owner)
        plugin.NeutronNetworkPlugin.allocate_network.reset_mock()

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

        self.assertRaises(exception.ManilaException,
                          self.bind_plugin._wait_for_ports_bind,
                          [fake_neut_port, fake_neut_port],
                          fake_share_server)

        self.bind_plugin.neutron_api.show_port.assert_called_once_with(
            fake_neutron_port['id'])
        self.sleep_mock.assert_not_called()

    @ddt.data(('DOWN', 'ACTIVE'), ('DOWN', 'DOWN'), ('ACTIVE', 'DOWN'))
    @mock.patch.object(time, 'time', side_effect=[1, 1, 3])
    def test_wait_for_bind_two_ports_no_bind(self, state, time_mock):
        fake_neut_port1 = copy.copy(fake_neutron_port)
        fake_neut_port1['status'] = state[0]
        fake_neut_port2 = copy.copy(fake_neutron_port)
        fake_neut_port2['status'] = state[1]
        self.mock_object(self.bind_plugin.neutron_api, 'show_port')
        self.bind_plugin.neutron_api.show_port.side_effect = [fake_neut_port1,
                                                              fake_neut_port2]

        self.assertRaises(exception.NetworkBindException,
                          self.bind_plugin._wait_for_ports_bind.__wrapped__,
                          self.bind_plugin,
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
                allocation_info={'count': 1})

            self.bind_plugin._has_provider_network_extension.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network)
            expected_kwargs = {
                'binding:vnic_type': 'baremetal',
                'host_id': 'foohost1',
                'network_id': fake_share_network['neutron_net_id'],
                'subnet_id': fake_share_network['neutron_subnet_id'],
                'device_owner': 'manila:share',
                'device_id': fake_share_network['id'],
            }
            self.bind_plugin.neutron_api.create_port.assert_called_once_with(
                fake_share_network['project_id'], **expected_kwargs)
            db_api.network_allocation_create.assert_called_once_with(
                self.fake_context,
                fake_network_allocation)
            self.bind_plugin._wait_for_ports_bind.assert_called_once_with(
                [db_api.network_allocation_create()], fake_share_server)


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

        with mock.patch.object(self.bind_plugin.neutron_api, 'create_port',
                               mock.Mock(return_value=fake_neutron_port)):
            self.bind_plugin.allocate_network(
                self.fake_context,
                fake_share_server,
                fake_share_network,
                allocation_info={'count': 1})

            self.bind_plugin._has_provider_network_extension.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network)
            expected_kwargs = {
                'binding:vnic_type': 'normal',
                'host_id': 'foohost1',
                'network_id': fake_share_network['neutron_net_id'],
                'subnet_id': fake_share_network['neutron_subnet_id'],
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
                allocation_info={'count': 1})

            self.bind_plugin._has_provider_network_extension.assert_any_call()
            save_nw_data.assert_called_once_with(self.fake_context,
                                                 fake_share_network)
            save_subnet_data.assert_called_once_with(self.fake_context,
                                                     fake_share_network)
            expected_kwargs = {
                'binding:vnic_type': 'normal',
                'host_id': 'foohost1',
                'network_id': fake_share_network['neutron_net_id'],
                'subnet_id': fake_share_network['neutron_subnet_id'],
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
