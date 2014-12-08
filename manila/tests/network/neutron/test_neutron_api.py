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
from neutronclient.common import exceptions as neutron_client_exc
from neutronclient.v2_0 import client as clientv20
from oslo.config import cfg

from manila import context
from manila.db import base
from manila import exception
from manila.network import neutron
from manila.network.neutron import api as neutron_api
from manila.network.neutron import constants as neutron_constants
from manila import test
from manila.tests.db import fakes

CONF = cfg.CONF


class FakeNeutronClient(object):

    def create_port(self, body):
        return body

    def delete_port(self, port_id):
        pass

    def show_port(self, port_id):
        pass

    def list_ports(self, **search_opts):
        pass

    def list_networks(self):
        pass

    def show_network(self, network_uuid):
        pass

    def show_subnet(self, subnet_uuid):
        pass

    def create_router(self, body):
        return body

    def list_routers(self):
        pass

    def create_network(self, body):
        return body

    def create_subnet(self, body):
        return body

    def update_port(self, port_id, body):
        return body

    def add_interface_router(self, router_id, subnet_id, port_id):
        pass

    def update_router(self, router_id, body):
        return body

    def show_router(self, router_id):
        pass

    def list_extensions(self):
        pass


class NeutronApiTest(test.TestCase):

    def setUp(self):
        super(NeutronApiTest, self).setUp()
        self._create_neutron_api()

    @mock.patch.object(base, 'Base', fakes.FakeModel)
    @mock.patch.object(context, 'get_admin_context',
                       mock.Mock(return_value='context'))
    @mock.patch.object(neutron, 'get_client',
                       mock.Mock(return_value=FakeNeutronClient()))
    def _create_neutron_api(self):
        self.neutron_api = neutron_api.API()

    @mock.patch.object(base.Base, '__init__', mock.Mock())
    @mock.patch.object(context, 'get_admin_context',
                       mock.Mock(return_value='context'))
    @mock.patch.object(neutron, 'get_client', mock.Mock())
    def test_create_api_object(self):
        neutron_api.API()

        context.get_admin_context.assert_called_once_with()
        neutron.get_client.assert_called_once_with('context')
        base.Base.__init__.assert_called_once_with()

    def test_create_port_with_all_args(self):
        port_args = {'tenant_id': 'test tenant', 'network_id': 'test net',
                     'host_id': 'test host', 'subnet_id': 'test subnet',
                     'fixed_ip': 'test ip', 'device_owner': 'test owner',
                     'device_id': 'test device', 'mac_address': 'test mac',
                     'security_group_ids': 'test group',
                     'dhcp_opts': 'test dhcp'}

        with mock.patch.object(self.neutron_api, '_has_port_binding_extension',
                               mock.Mock(return_value=True)):
            port = self.neutron_api.create_port(**port_args)
            self.assertEqual(port['tenant_id'], port_args['tenant_id'])
            self.assertEqual(port['network_id'],
                             port_args['network_id'])
            self.assertEqual(port['binding:host_id'],
                             port_args['host_id'])
            self.assertEqual(port['fixed_ips'][0]['subnet_id'],
                             port_args['subnet_id'])
            self.assertEqual(port['fixed_ips'][0]['ip_address'],
                             port_args['fixed_ip'])
            self.assertEqual(port['device_owner'],
                             port_args['device_owner'])
            self.assertEqual(port['device_id'], port_args['device_id'])
            self.assertEqual(port['mac_address'],
                             port_args['mac_address'])
            self.assertEqual(port['security_groups'],
                             port_args['security_group_ids'])
            self.assertEqual(port['extra_dhcp_opts'],
                             port_args['dhcp_opts'])

    def test_create_port_with_required_args(self):
        port_args = {'tenant_id': 'test tenant', 'network_id': 'test net'}

        with mock.patch.object(self.neutron_api, '_has_port_binding_extension',
                               mock.Mock(return_value=True)):

            port = self.neutron_api.create_port(**port_args)
            self.assertEqual(port['tenant_id'], port_args['tenant_id'])
            self.assertEqual(port['network_id'],
                             port_args['network_id'])

    @mock.patch.object(neutron_api.LOG, 'exception', mock.Mock())
    def test_create_port_exception(self):
        port_args = {'tenant_id': 'test tenant', 'network_id': 'test net'}
        client_create_port_mock = mock.Mock(
            side_effect=neutron_client_exc.NeutronClientException)

        with mock.patch.object(self.neutron_api, '_has_port_binding_extension',
                               mock.Mock(return_value=True)):
            with mock.patch.object(self.neutron_api.client, 'create_port',
                                   client_create_port_mock):

                self.assertRaises(exception.NetworkException,
                                  self.neutron_api.create_port,
                                  **port_args)
                self.assertTrue(neutron_api.LOG.exception.called)

    @mock.patch.object(neutron_api.LOG, 'exception', mock.Mock())
    def test_create_port_exception_status_409(self):
        port_args = {'tenant_id': 'test tenant', 'network_id': 'test net'}
        client_create_port_mock = mock.Mock(
            side_effect=neutron_client_exc.NeutronClientException(
                status_code=409))

        with mock.patch.object(self.neutron_api, '_has_port_binding_extension',
                               mock.Mock(return_value=True)):
            with mock.patch.object(self.neutron_api.client, 'create_port',
                                   client_create_port_mock):

                self.assertRaises(exception.PortLimitExceeded,
                                  self.neutron_api.create_port,
                                  **port_args)
                self.assertTrue(neutron_api.LOG.exception.called)

    def test_delete_port(self):
        port_id = 'test port id'
        with mock.patch.object(self.neutron_api.client, 'delete_port',
                               mock.Mock()) as client_delete_port_mock:

            self.neutron_api.delete_port(port_id)
            client_delete_port_mock.assert_called_once_with(port_id)

    def test_list_ports(self):
        search_opts = {'test_option': 'test_value'}
        fake_ports = [{'fake port': 'fake port info'}]
        client_list_ports_mock = mock.Mock(return_value={'ports': fake_ports})

        with mock.patch.object(self.neutron_api.client, 'list_ports',
                               client_list_ports_mock):

            ports = self.neutron_api.list_ports(**search_opts)
            client_list_ports_mock.assert_called_once_with(**search_opts)
            self.assertEqual(ports, fake_ports)

    def test_show_port(self):
        port_id = 'test port id'
        fake_port = {'fake port': 'fake port info'}
        client_show_port_mock = mock.Mock(return_value={'port': fake_port})

        with mock.patch.object(self.neutron_api.client, 'show_port',
                               client_show_port_mock):

            port = self.neutron_api.show_port(port_id)
            client_show_port_mock.assert_called_once_with(port_id)
            self.assertEqual(port, fake_port)

    def test_get_network(self):
        network_id = 'test network id'
        fake_network = {'fake network': 'fake network info'}
        client_show_network_mock = mock.Mock(
            return_value={'network': fake_network})

        with mock.patch.object(self.neutron_api.client, 'show_network',
                               client_show_network_mock):

            network = self.neutron_api.get_network(network_id)
            client_show_network_mock.assert_called_once_with(network_id)
            self.assertEqual(network, fake_network)

    def test_get_subnet(self):
        subnet_id = 'fake subnet id'

        with mock.patch.object(self.neutron_api.client, 'show_subnet',
                               mock.Mock(return_value={'subnet': {}})):

            subnet = self.neutron_api.get_subnet(subnet_id)
            self.neutron_api.client.show_subnet.assert_called_once_with(
                subnet_id)
            self.assertEqual(subnet, {})

    def test_get_all_network(self):
        fake_networks = [{'fake network': 'fake network info'}]
        client_list_networks_mock = mock.Mock(
            return_value={'networks': fake_networks})

        with mock.patch.object(self.neutron_api.client, 'list_networks',
                               client_list_networks_mock):

            networks = self.neutron_api.get_all_networks()
            client_list_networks_mock.assert_any_call()
            self.assertEqual(networks, fake_networks)

    def test_list_extensions(self):
        extensions = [{'name': neutron_constants.PORTBINDING_EXT},
                      {'name': neutron_constants.PROVIDER_NW_EXT}]

        with mock.patch.object(
                self.neutron_api.client,
                'list_extensions',
                mock.Mock(return_value={'extensions': extensions})):

            result = self.neutron_api.list_extensions()
            self.neutron_api.client.list_extensions.assert_any_call()
            self.assertTrue(neutron_constants.PORTBINDING_EXT in result)
            self.assertTrue(neutron_constants.PROVIDER_NW_EXT in result)
            self.assertEqual(result[neutron_constants.PORTBINDING_EXT],
                             extensions[0])
            self.assertEqual(result[neutron_constants.PROVIDER_NW_EXT],
                             extensions[1])

    def test_create_network(self):
        net_args = {'tenant_id': 'test tenant', 'name': 'test name'}

        network = self.neutron_api.network_create(**net_args)
        self.assertEqual(network['tenant_id'], net_args['tenant_id'])
        self.assertEqual(network['name'], net_args['name'])

    def test_create_subnet(self):
        subnet_args = {'tenant_id': 'test tenant', 'name': 'test name',
                       'net_id': 'test net id', 'cidr': '10.0.0.0/24'}

        subnet = self.neutron_api.subnet_create(**subnet_args)
        self.assertEqual(subnet['tenant_id'], subnet_args['tenant_id'])
        self.assertEqual(subnet['name'], subnet_args['name'])

    def test_create_router(self):
        router_args = {'tenant_id': 'test tenant', 'name': 'test name'}

        router = self.neutron_api.router_create(**router_args)
        self.assertEqual(router['tenant_id'], router_args['tenant_id'])
        self.assertEqual(router['name'], router_args['name'])

    def test_list_routers(self):
        fake_routers = [{'fake router': 'fake router info'}]
        client_list_routers_mock = mock.Mock(
            return_value={'routers': fake_routers})

        with mock.patch.object(self.neutron_api.client, 'list_routers',
                               client_list_routers_mock):

            networks = self.neutron_api.router_list()
            client_list_routers_mock.assert_any_call()
            self.assertEqual(networks, fake_routers)

    def test_create_network_exception(self):
        net_args = {'tenant_id': 'test tenant', 'name': 'test name'}
        self.stubs.Set(
            self.neutron_api.client, 'create_network',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.network_create,
            **net_args)

    def test_create_subnet_exception(self):
        subnet_args = {'tenant_id': 'test tenant', 'name': 'test name',
                       'net_id': 'test net id', 'cidr': '10.0.0.0/24'}
        self.stubs.Set(
            self.neutron_api.client, 'create_subnet',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.subnet_create,
            **subnet_args)

    def test_create_router_exception(self):
        router_args = {'tenant_id': 'test tenant', 'name': 'test name'}
        self.stubs.Set(
            self.neutron_api.client, 'create_router',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.router_create,
            **router_args)

    def test_update_port_fixed_ips(self):
        port_id = 'test_port'
        fixed_ips = {'fixed_ips': [{'subnet_id': 'test subnet'}]}
        port = self.neutron_api.update_port_fixed_ips(port_id, fixed_ips)
        self.assertEqual(port, fixed_ips)

    def test_update_port_fixed_ips_exception(self):
        port_id = 'test_port'
        fixed_ips = {'fixed_ips': [{'subnet_id': 'test subnet'}]}
        self.stubs.Set(
            self.neutron_api.client, 'update_port',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.update_port_fixed_ips,
            port_id, fixed_ips)

    def test_router_update_routes(self):
        router_id = 'test_router'
        routes = {'routes': [{'destination': '0.0.0.0/0',
                              'nexthop': '8.8.8.8'}]}
        router = self.neutron_api.router_update_routes(router_id, routes)
        self.assertEqual(router, routes)

    def test_router_update_routes_exception(self):
        router_id = 'test_router'
        routes = {'routes': [{'destination': '0.0.0.0/0',
                              'nexthop': '8.8.8.8'}]}
        self.stubs.Set(
            self.neutron_api.client, 'update_router',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.router_update_routes,
            router_id, routes)

    def test_show_router(self):
        router_id = 'test router id'
        fake_router = {'fake router': 'fake router info'}
        client_show_router_mock = mock.Mock(return_value={'router':
                                                          fake_router})

        with mock.patch.object(self.neutron_api.client, 'show_router',
                               client_show_router_mock):

            port = self.neutron_api.show_router(router_id)
            client_show_router_mock.assert_called_once_with(router_id)
            self.assertEqual(port, fake_router)

    def test_router_add_interface(self):
        router_id = 'test port id'
        subnet_id = 'test subnet id'
        port_id = 'test port id'
        with mock.patch.object(
                self.neutron_api.client, 'add_interface_router',
                mock.Mock()) as client_add_interface_router_mock:

            self.neutron_api.router_add_interface(router_id,
                                                  subnet_id,
                                                  port_id)
            client_add_interface_router_mock.assert_called_once_with(
                port_id, {'subnet_id': subnet_id, 'port_id': port_id})

    def test_router_add_interface_exception(self):
        router_id = 'test port id'
        subnet_id = 'test subnet id'
        port_id = 'test port id'
        self.stubs.Set(
            self.neutron_api.client, 'add_interface_router',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.router_add_interface,
            router_id, subnet_id, port_id)


class TestNeutronClient(test.TestCase):

    @mock.patch.object(clientv20.Client, '__init__',
                       mock.Mock(return_value=None))
    def test_get_client_with_token(self):
        client_args = {'endpoint_url': CONF.neutron_url,
                       'timeout': CONF.neutron_url_timeout,
                       'insecure': CONF.neutron_api_insecure,
                       'ca_cert': CONF.neutron_ca_certificates_file,
                       'token': 'test_token',
                       'auth_strategy': None}
        my_context = context.RequestContext('test_user', 'test_tenant',
                                            auth_token='test_token',
                                            is_admin=False)

        neutron.get_client(my_context)
        clientv20.Client.__init__.assert_called_once_with(**client_args)

    @mock.patch.object(clientv20.Client, '__init__',
                       mock.Mock(return_value=None))
    def test_get_client_no_token(self):
        my_context = context.RequestContext('test_user', 'test_tenant',
                                            is_admin=False)

        self.assertRaises(neutron_client_exc.Unauthorized,
                          neutron.get_client,
                          my_context)

    @mock.patch.object(clientv20.Client, '__init__',
                       mock.Mock(return_value=None))
    def test_get_client_admin_context(self):
        client_args = {'endpoint_url': CONF.neutron_url,
                       'timeout': CONF.neutron_url_timeout,
                       'insecure': CONF.neutron_api_insecure,
                       'ca_cert': CONF.neutron_ca_certificates_file,
                       'username': CONF.neutron_admin_username,
                       'tenant_name': CONF.neutron_admin_tenant_name,
                       'password': CONF.neutron_admin_password,
                       'auth_url': CONF.neutron_admin_auth_url,
                       'auth_strategy': CONF.neutron_auth_strategy}
        my_context = context.RequestContext('test_user', 'test_tenant',
                                            is_admin=True)

        neutron.get_client(my_context)
        clientv20.Client.__init__.assert_called_once_with(**client_args)
