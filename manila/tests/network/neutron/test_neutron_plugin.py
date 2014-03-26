# Copyright 2013 OpenStack Foundation
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
import mock
import unittest

from manila.common import constants
from manila import context
from manila.db import api as db_api
from manila import exception
from manila.network.neutron import constants as neutron_constants
from manila.network.neutron import neutron_network_plugin as plugin

fake_neutron_port = {
        "status": "test_port_status",
        "allowed_address_pairs": [],
        "admin_state_up": True,
        "network_id": "test_net_id",
        "tenant_id": "fake_tenant_id",
        "extra_dhcp_opts": [],
        "device_owner": "test",
        "binding:capabilities": {"port_filter": True},
        "mac_address": "test_mac",
        "fixed_ips": [
            {"subnet_id": "test_subnet_id",
             "ip_address": "test_ip"}
        ],
        "id": "test_port_id",
        "security_groups": ["fake_sec_group_id"],
        "device_id": "fake_device_id"
    }

fake_share_network = {'id': 'fake nw info id',
                      'neutron_subnet_id': 'fake subnet id',
                      'neutron_net_id': 'fake net id',
                      'project_id': 'fake project id',
                      'status': 'test_subnet_status',
                      'name': 'fake name',
                      'description': 'fake description',
                      'network_allocations': [],
                      'security_services': [],
                      'shares': []}

fake_network_allocation = \
    {'id': fake_neutron_port['id'],
     'share_network_id': fake_share_network['id'],
     'ip_address': fake_neutron_port['fixed_ips'][0]['ip_address'],
     'mac_address': fake_neutron_port['mac_address'],
     'status': constants.STATUS_ACTIVE}


class NeutronNetworkPluginTest(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(NeutronNetworkPluginTest, self).__init__(*args, **kwargs)

        self.plugin = plugin.NeutronNetworkPlugin()
        self.plugin.db = db_api
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)

    @mock.patch.object(db_api, 'network_allocation_create',
                       mock.Mock(return_values=fake_network_allocation))
    @mock.patch.object(db_api, 'share_network_get',
                       mock.Mock(return_value=fake_share_network))
    def test_allocate_network_one_allocation(self):
        has_provider_nw_ext = mock.patch.object(self.plugin,
                                '_has_provider_network_extension').start()
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
                device_owner='manila:share')
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
    def test_allocate_network_two_allocation(self):
        has_provider_nw_ext = mock.patch.object(self.plugin,
                                '_has_provider_network_extension').start()
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
                fake_share_network,
                count=2)

            neutron_api_calls = [
                mock.call(fake_share_network['project_id'],
                          network_id=fake_share_network['neutron_net_id'],
                          subnet_id=fake_share_network['neutron_subnet_id'],
                          device_owner='manila:share'),
                mock.call(fake_share_network['project_id'],
                          network_id=fake_share_network['neutron_net_id'],
                          subnet_id=fake_share_network['neutron_subnet_id'],
                          device_owner='manila:share'),
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
        has_provider_nw_ext = mock.patch.object(self.plugin,
                                '_has_provider_network_extension').start()
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
                          fake_share_network)

        has_provider_nw_ext.stop()
        save_nw_data.stop()
        save_subnet_data.stop()
        create_port.stop()

    @mock.patch.object(db_api, 'network_allocation_delete', mock.Mock())
    @mock.patch.object(db_api, 'share_network_update', mock.Mock())
    def test_deallocate_network_nominal(self):
        share_nw = {'id': fake_share_network['id']}
        share_nw['network_allocations'] = [fake_network_allocation]

        with mock.patch.object(self.plugin.neutron_api, 'delete_port',
                               mock.Mock()):
            self.plugin.deallocate_network(self.fake_context, share_nw)
            self.plugin.neutron_api.delete_port.assert_called_once_with(
                fake_network_allocation['id'])
            db_api.network_allocation_delete.assert_called_once_with(
                self.fake_context,
                fake_network_allocation['id'])

    @mock.patch.object(db_api, 'share_network_update',
                       mock.Mock(return_value=fake_share_network))
    @mock.patch.object(db_api, 'network_allocation_update', mock.Mock())
    def test_deallocate_network_neutron_api_exception(self):
        share_nw = {'id': fake_share_network['id']}
        share_nw['network_allocations'] = [fake_network_allocation]

        delete_port = mock.patch.object(self.plugin.neutron_api,
                                        'delete_port').start()
        delete_port.side_effect = exception.NetworkException

        self.assertRaises(exception.NetworkException,
                          self.plugin.deallocate_network,
                          self.fake_context,
                          share_nw)
        db_api.network_allocation_update.assert_called_once_with(
                                self.fake_context,
                                fake_network_allocation['id'],
                                {'status': constants.STATUS_ERROR})
        delete_port.stop()

    @mock.patch.object(db_api, 'share_network_update', mock.Mock())
    def test_save_neutron_network_data(self):
        neutron_nw_info = {'provider:network_type': 'vlan',
                           'provider:segmentation_id': 1000}
        share_nw_update_dict = {'network_type': 'vlan',
                                'segmentation_id': 1000}

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
        neutron_subnet_info = {'cidr': '10.0.0.0/24',
                               'ip_version': 4}

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
                neutron_subnet_info)

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
