# Copyright 2013 OpenStack Foundation
# Copyright 2014 Mirantis Inc.
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
from oslo_config import cfg

from manila.db import base
from manila import exception
from manila.network.neutron import api as neutron_api
from manila.network.neutron import constants as neutron_constants
from manila import test
from manila.tests.db import fakes
from manila.tests import utils as test_utils

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


class NeutronclientTestCase(test.TestCase):

    def test_no_auth_obj(self):
        mock_client_loader = self.mock_object(
            neutron_api.client_auth, 'AuthClientLoader')
        fake_context = 'fake_context'
        data = {
            'DEFAULT': {
                'neutron_admin_username': 'foo_username',
                'neutron_admin_password': 'foo_password',
                'neutron_admin_tenant_name': 'foo_tenant_name',
                'neutron_admin_auth_url': 'foo_auth_url',
            },
            'neutron': {
                'endpoint_type': 'foo_endpoint_type',
                'region_name': 'foo_region_name',
            }
        }

        self.client = None
        with test_utils.create_temp_config_with_opts(data):
            self.client = neutron_api.API()
            self.client.get_client(fake_context)

        mock_client_loader.assert_called_once_with(
            client_class=neutron_api.clientv20.Client,
            exception_module=neutron_api.neutron_client_exc,
            cfg_group=neutron_api.NEUTRON_GROUP,
            deprecated_opts_for_v2={
                'username': data['DEFAULT']['neutron_admin_username'],
                'password': data['DEFAULT']['neutron_admin_password'],
                'tenant_name': data['DEFAULT']['neutron_admin_tenant_name'],
                'auth_url': data['DEFAULT']['neutron_admin_auth_url'],
            },
        )
        mock_client_loader.return_value.get_client.assert_called_once_with(
            self.client,
            fake_context,
            endpoint_type=data['neutron']['endpoint_type'],
            region_name=data['neutron']['region_name'],
        )

    def test_with_auth_obj(self):
        fake_context = 'fake_context'
        data = {
            'neutron': {
                'endpoint_type': 'foo_endpoint_type',
                'region_name': 'foo_region_name',
            }
        }

        self.client = None
        with test_utils.create_temp_config_with_opts(data):
            self.client = neutron_api.API()
            self.client.auth_obj = type(
                'FakeAuthObj', (object, ), {'get_client': mock.Mock()})
            self.client.get_client(fake_context)

        self.client.auth_obj.get_client.assert_called_once_with(
            self.client,
            fake_context,
            endpoint_type=data['neutron']['endpoint_type'],
            region_name=data['neutron']['region_name'],
        )


class NeutronApiTest(test.TestCase):

    def setUp(self):
        super(NeutronApiTest, self).setUp()
        self.mock_object(base, 'Base', fakes.FakeModel)
        self.mock_object(
            clientv20, 'Client', mock.Mock(return_value=FakeNeutronClient()))
        self.neutron_api = neutron_api.API()

    def test_create_api_object(self):
        # instantiate Neutron API object
        neutron_api_instance = neutron_api.API()

        # Verify results
        self.assertTrue(hasattr(neutron_api_instance, 'client'))
        self.assertTrue(hasattr(neutron_api_instance, 'configuration'))
        self.assertEqual('DEFAULT', neutron_api_instance.config_group_name)

    def test_create_api_object_custom_config_group(self):
        # Set up test data
        fake_config_group_name = 'fake_config_group_name'

        # instantiate Neutron API object
        obj = neutron_api.API(fake_config_group_name)
        obj.get_client(mock.Mock())

        # Verify results
        self.assertTrue(clientv20.Client.called)
        self.assertTrue(hasattr(obj, 'client'))
        self.assertTrue(hasattr(obj, 'configuration'))
        self.assertEqual(
            fake_config_group_name, obj.configuration._group.name)

    def test_create_port_with_all_args(self):
        # Set up test data
        self.mock_object(self.neutron_api, '_has_port_binding_extension',
                         mock.Mock(return_value=True))
        port_args = {
            'tenant_id': 'test tenant', 'network_id': 'test net',
            'host_id': 'test host', 'subnet_id': 'test subnet',
            'fixed_ip': 'test ip', 'device_owner': 'test owner',
            'device_id': 'test device', 'mac_address': 'test mac',
            'security_group_ids': 'test group',
            'dhcp_opts': 'test dhcp',
        }

        # Execute method 'create_port'
        port = self.neutron_api.create_port(**port_args)

        # Verify results
        self.assertEqual(port_args['tenant_id'], port['tenant_id'])
        self.assertEqual(port_args['network_id'], port['network_id'])
        self.assertEqual(port_args['host_id'], port['binding:host_id'])
        self.assertEqual(port_args['subnet_id'],
                         port['fixed_ips'][0]['subnet_id'])
        self.assertEqual(port_args['fixed_ip'],
                         port['fixed_ips'][0]['ip_address'])
        self.assertEqual(port_args['device_owner'], port['device_owner'])
        self.assertEqual(port_args['device_id'], port['device_id'])
        self.assertEqual(port_args['mac_address'], port['mac_address'])
        self.assertEqual(port_args['security_group_ids'],
                         port['security_groups'])
        self.assertEqual(port_args['dhcp_opts'], port['extra_dhcp_opts'])
        self.neutron_api._has_port_binding_extension.assert_called_once_with()
        self.assertTrue(clientv20.Client.called)

    def test_create_port_with_required_args(self):
        # Set up test data
        port_args = {'tenant_id': 'test tenant', 'network_id': 'test net'}

        # Execute method 'create_port'
        port = self.neutron_api.create_port(**port_args)

        # Verify results
        self.assertEqual(port_args['tenant_id'], port['tenant_id'])
        self.assertEqual(port_args['network_id'],
                         port['network_id'])
        self.assertTrue(clientv20.Client.called)

    def test_create_port_with_additional_kwargs(self):
        # Set up test data
        port_args = {'tenant_id': 'test tenant', 'network_id': 'test net',
                     'binding_arg': 'foo'}

        # Execute method 'create_port'
        port = self.neutron_api.create_port(**port_args)

        # Verify results
        self.assertEqual(port_args['tenant_id'], port['tenant_id'])
        self.assertEqual(port_args['network_id'],
                         port['network_id'])
        self.assertEqual(port_args['binding_arg'],
                         port['binding_arg'])
        self.assertTrue(clientv20.Client.called)

    def test_create_port_with_host_id_no_binding_ext(self):
        self.mock_object(self.neutron_api, '_has_port_binding_extension',
                         mock.Mock(return_value=False))
        port_args = {
            'tenant_id': 'test tenant',
            'network_id': 'test net',
            'host_id': 'foohost'
        }

        self.assertRaises(exception.NetworkException,
                          self.neutron_api.create_port, **port_args)

    @mock.patch.object(neutron_api.LOG, 'exception', mock.Mock())
    def test_create_port_exception(self):
        self.mock_object(
            self.neutron_api.client, 'create_port',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))
        port_args = {'tenant_id': 'test tenant', 'network_id': 'test net'}

        # Execute method 'create_port'
        self.assertRaises(exception.NetworkException,
                          self.neutron_api.create_port,
                          **port_args)

        # Verify results
        self.assertTrue(neutron_api.LOG.exception.called)
        self.assertTrue(clientv20.Client.called)
        self.assertTrue(self.neutron_api.client.create_port.called)

    @mock.patch.object(neutron_api.LOG, 'exception', mock.Mock())
    def test_create_port_exception_status_409(self):
        # Set up test data
        self.mock_object(
            self.neutron_api.client, 'create_port',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException(
                status_code=409)))
        port_args = {'tenant_id': 'test tenant', 'network_id': 'test net'}

        # Execute method 'create_port'
        self.assertRaises(exception.PortLimitExceeded,
                          self.neutron_api.create_port,
                          **port_args)

        # Verify results
        self.assertTrue(neutron_api.LOG.exception.called)
        self.assertTrue(clientv20.Client.called)
        self.assertTrue(self.neutron_api.client.create_port.called)

    def test_delete_port(self):
        # Set up test data
        self.mock_object(self.neutron_api.client, 'delete_port')
        port_id = 'test port id'

        # Execute method 'delete_port'
        self.neutron_api.delete_port(port_id)

        # Verify results
        self.neutron_api.client.delete_port.assert_called_once_with(port_id)
        self.assertTrue(clientv20.Client.called)

    def test_list_ports(self):
        # Set up test data
        search_opts = {'test_option': 'test_value'}
        fake_ports = [{'fake port': 'fake port info'}]
        self.mock_object(
            self.neutron_api.client, 'list_ports',
            mock.Mock(return_value={'ports': fake_ports}))

        # Execute method 'list_ports'
        ports = self.neutron_api.list_ports(**search_opts)

        # Verify results
        self.assertEqual(fake_ports, ports)
        self.assertTrue(clientv20.Client.called)
        self.neutron_api.client.list_ports.assert_called_once_with(
            **search_opts)

    def test_show_port(self):
        # Set up test data
        port_id = 'test port id'
        fake_port = {'fake port': 'fake port info'}
        self.mock_object(
            self.neutron_api.client, 'show_port',
            mock.Mock(return_value={'port': fake_port}))

        # Execute method 'show_port'
        port = self.neutron_api.show_port(port_id)

        # Verify results
        self.assertEqual(fake_port, port)
        self.assertTrue(clientv20.Client.called)
        self.neutron_api.client.show_port.assert_called_once_with(port_id)

    def test_get_network(self):
        # Set up test data
        network_id = 'test network id'
        fake_network = {'fake network': 'fake network info'}
        self.mock_object(
            self.neutron_api.client, 'show_network',
            mock.Mock(return_value={'network': fake_network}))

        # Execute method 'get_network'
        network = self.neutron_api.get_network(network_id)

        # Verify results
        self.assertEqual(fake_network, network)
        self.assertTrue(clientv20.Client.called)
        self.neutron_api.client.show_network.assert_called_once_with(
            network_id)

    def test_get_subnet(self):
        # Set up test data
        subnet_id = 'fake subnet id'
        self.mock_object(
            self.neutron_api.client, 'show_subnet',
            mock.Mock(return_value={'subnet': {}}))

        # Execute method 'get_subnet'
        subnet = self.neutron_api.get_subnet(subnet_id)

        # Verify results
        self.assertEqual({}, subnet)
        self.assertTrue(clientv20.Client.called)
        self.neutron_api.client.show_subnet.assert_called_once_with(
            subnet_id)

    def test_get_all_network(self):
        # Set up test data
        fake_networks = [{'fake network': 'fake network info'}]
        self.mock_object(
            self.neutron_api.client, 'list_networks',
            mock.Mock(return_value={'networks': fake_networks}))

        # Execute method 'get_all_networks'
        networks = self.neutron_api.get_all_networks()

        # Verify results
        self.assertEqual(fake_networks, networks)
        self.assertTrue(clientv20.Client.called)
        self.neutron_api.client.list_networks.assert_called_once_with()

    def test_list_extensions(self):
        # Set up test data
        extensions = [
            {'name': neutron_constants.PORTBINDING_EXT},
            {'name': neutron_constants.PROVIDER_NW_EXT},
        ]
        self.mock_object(
            self.neutron_api.client, 'list_extensions',
            mock.Mock(return_value={'extensions': extensions}))

        # Execute method 'list_extensions'
        result = self.neutron_api.list_extensions()

        # Verify results
        self.assertTrue(clientv20.Client.called)
        self.neutron_api.client.list_extensions.assert_called_once_with()
        self.assertIn(neutron_constants.PORTBINDING_EXT, result)
        self.assertIn(neutron_constants.PROVIDER_NW_EXT, result)
        self.assertEqual(
            extensions[0], result[neutron_constants.PORTBINDING_EXT])
        self.assertEqual(
            extensions[1], result[neutron_constants.PROVIDER_NW_EXT])

    def test_create_network(self):
        # Set up test data
        net_args = {'tenant_id': 'test tenant', 'name': 'test name'}

        # Execute method 'network_create'
        network = self.neutron_api.network_create(**net_args)

        # Verify results
        self.assertEqual(net_args['tenant_id'], network['tenant_id'])
        self.assertEqual(net_args['name'], network['name'])
        self.assertTrue(clientv20.Client.called)

    def test_create_subnet(self):
        # Set up test data
        subnet_args = {
            'tenant_id': 'test tenant',
            'name': 'test name',
            'net_id': 'test net id',
            'cidr': '10.0.0.0/24',
        }

        # Execute method 'subnet_create'
        subnet = self.neutron_api.subnet_create(**subnet_args)

        # Verify results
        self.assertEqual(subnet_args['tenant_id'], subnet['tenant_id'])
        self.assertEqual(subnet_args['name'], subnet['name'])
        self.assertTrue(clientv20.Client.called)

    def test_create_router(self):
        # Set up test data
        router_args = {'tenant_id': 'test tenant', 'name': 'test name'}

        # Execute method 'router_create'
        router = self.neutron_api.router_create(**router_args)

        # Verify results
        self.assertEqual(router_args['tenant_id'], router['tenant_id'])
        self.assertEqual(router_args['name'], router['name'])
        self.assertTrue(clientv20.Client.called)

    def test_list_routers(self):
        # Set up test data
        fake_routers = [{'fake router': 'fake router info'}]
        self.mock_object(
            self.neutron_api.client, 'list_routers',
            mock.Mock(return_value={'routers': fake_routers}))

        # Execute method 'router_list'
        networks = self.neutron_api.router_list()

        # Verify results
        self.assertEqual(fake_routers, networks)
        self.assertTrue(clientv20.Client.called)
        self.neutron_api.client.list_routers.assert_called_once_with()

    def test_create_network_exception(self):
        # Set up test data
        net_args = {'tenant_id': 'test tenant', 'name': 'test name'}
        self.mock_object(
            self.neutron_api.client, 'create_network',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))

        # Execute method 'network_create'
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.network_create,
            **net_args)

        # Verify results
        self.neutron_api.client.create_network.assert_called_once_with(
            {'network': net_args})
        self.assertTrue(clientv20.Client.called)

    def test_create_subnet_exception(self):
        # Set up test data
        subnet_args = {
            'tenant_id': 'test tenant',
            'name': 'test name',
            'net_id': 'test net id',
            'cidr': '10.0.0.0/24',
        }
        self.mock_object(
            self.neutron_api.client, 'create_subnet',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))

        # Execute method 'subnet_create'
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.subnet_create,
            **subnet_args)

        # Verify results
        expected_data = {
            'network_id': subnet_args['net_id'],
            'tenant_id': subnet_args['tenant_id'],
            'cidr': subnet_args['cidr'],
            'name': subnet_args['name'],
            'ip_version': 4,
        }
        self.neutron_api.client.create_subnet.assert_called_once_with(
            {'subnet': expected_data})
        self.assertTrue(clientv20.Client.called)

    def test_create_router_exception(self):
        # Set up test data
        router_args = {'tenant_id': 'test tenant', 'name': 'test name'}
        self.mock_object(
            self.neutron_api.client, 'create_router',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))

        # Execute method 'router_create'
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.router_create,
            **router_args)

        # Verify results
        self.neutron_api.client.create_router.assert_called_once_with(
            {'router': router_args})
        self.assertTrue(clientv20.Client.called)

    def test_update_port_fixed_ips(self):
        # Set up test data
        port_id = 'test_port'
        fixed_ips = {'fixed_ips': [{'subnet_id': 'test subnet'}]}

        # Execute method 'update_port_fixed_ips'
        port = self.neutron_api.update_port_fixed_ips(port_id, fixed_ips)

        # Verify results
        self.assertEqual(fixed_ips, port)
        self.assertTrue(clientv20.Client.called)

    def test_update_port_fixed_ips_exception(self):
        # Set up test data
        port_id = 'test_port'
        fixed_ips = {'fixed_ips': [{'subnet_id': 'test subnet'}]}
        self.mock_object(
            self.neutron_api.client, 'update_port',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))

        # Execute method 'update_port_fixed_ips'
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.update_port_fixed_ips,
            port_id, fixed_ips)

        # Verify results
        self.neutron_api.client.update_port.assert_called_once_with(
            port_id, {'port': fixed_ips})
        self.assertTrue(clientv20.Client.called)

    def test_router_update_routes(self):
        # Set up test data
        router_id = 'test_router'
        routes = {
            'routes': [
                {'destination': '0.0.0.0/0', 'nexthop': '8.8.8.8', },
            ],
        }

        # Execute method 'router_update_routes'
        router = self.neutron_api.router_update_routes(router_id, routes)

        # Verify results
        self.assertEqual(routes, router)
        self.assertTrue(clientv20.Client.called)

    def test_router_update_routes_exception(self):
        # Set up test data
        router_id = 'test_router'
        routes = {
            'routes': [
                {'destination': '0.0.0.0/0', 'nexthop': '8.8.8.8', },
            ],
        }
        self.mock_object(
            self.neutron_api.client, 'update_router',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))

        # Execute method 'router_update_routes'
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.router_update_routes,
            router_id, routes)

        # Verify results
        self.neutron_api.client.update_router.assert_called_once_with(
            router_id, {'router': routes})
        self.assertTrue(clientv20.Client.called)

    def test_show_router(self):
        # Set up test data
        router_id = 'test router id'
        fake_router = {'fake router': 'fake router info'}
        self.mock_object(
            self.neutron_api.client, 'show_router',
            mock.Mock(return_value={'router': fake_router}))

        # Execute method 'show_router'
        port = self.neutron_api.show_router(router_id)

        # Verify results
        self.assertEqual(fake_router, port)
        self.assertTrue(clientv20.Client.called)
        self.neutron_api.client.show_router.assert_called_once_with(router_id)

    def test_router_add_interface(self):
        # Set up test data
        router_id = 'test port id'
        subnet_id = 'test subnet id'
        port_id = 'test port id'
        self.mock_object(self.neutron_api.client, 'add_interface_router')

        # Execute method 'router_add_interface'
        self.neutron_api.router_add_interface(router_id, subnet_id, port_id)

        # Verify results
        self.neutron_api.client.add_interface_router.assert_called_once_with(
            port_id, {'subnet_id': subnet_id, 'port_id': port_id})
        self.assertTrue(clientv20.Client.called)

    def test_router_add_interface_exception(self):
        # Set up test data
        router_id = 'test port id'
        subnet_id = 'test subnet id'
        port_id = 'test port id'
        self.mock_object(
            self.neutron_api.client, 'add_interface_router',
            mock.Mock(side_effect=neutron_client_exc.NeutronClientException))

        # Execute method 'router_add_interface'
        self.assertRaises(
            exception.NetworkException,
            self.neutron_api.router_add_interface,
            router_id, subnet_id, port_id)

        # Verify results
        self.neutron_api.client.add_interface_router.assert_called_once_with(
            router_id, {'subnet_id': subnet_id, 'port_id': port_id})
        self.assertTrue(clientv20.Client.called)

    def test_admin_project_id_exist(self):
        fake_admin_project_id = 'fake_admin_project_id_value'
        self.neutron_api.client.httpclient = mock.Mock()
        self.neutron_api.client.httpclient.auth_token = mock.Mock()
        self.neutron_api.client.httpclient.get_project_id = mock.Mock(
            return_value=fake_admin_project_id)

        admin_project_id = self.neutron_api.admin_project_id

        self.assertEqual(fake_admin_project_id, admin_project_id)
        self.neutron_api.client.httpclient.auth_token.called

    def test_admin_project_id_not_exist(self):
        fake_admin_project_id = 'fake_admin_project_id_value'
        self.neutron_api.client.httpclient = mock.Mock()
        self.neutron_api.client.httpclient.auth_token = mock.Mock(
            return_value=None)
        self.neutron_api.client.httpclient.authenticate = mock.Mock()
        self.neutron_api.client.httpclient.get_project_id = mock.Mock(
            return_value=fake_admin_project_id)

        admin_project_id = self.neutron_api.admin_project_id

        self.assertEqual(fake_admin_project_id, admin_project_id)
        self.neutron_api.client.httpclient.auth_token.called
        self.neutron_api.client.httpclient.authenticate.called

    def test_admin_project_id_not_exist_with_failure(self):
        self.neutron_api.client.httpclient = mock.Mock()
        self.neutron_api.client.httpclient.auth_token = None
        self.neutron_api.client.httpclient.authenticate = mock.Mock(
            side_effect=neutron_client_exc.NeutronClientException)
        self.neutron_api.client.httpclient.auth_tenant_id = mock.Mock()

        try:
            self.neutron_api.admin_project_id
        except exception.NetworkException:
            pass
        else:
            raise Exception('Expected error was not raised')

        self.assertTrue(self.neutron_api.client.httpclient.authenticate.called)
        self.assertFalse(
            self.neutron_api.client.httpclient.auth_tenant_id.called)

    def test_get_all_admin_project_networks(self):
        fake_networks = {'networks': ['fake_net_1', 'fake_net_2']}
        self.mock_object(
            self.neutron_api.client, 'list_networks',
            mock.Mock(return_value=fake_networks))
        self.neutron_api.client.httpclient = mock.Mock()
        self.neutron_api.client.httpclient.auth_token = mock.Mock()
        self.neutron_api.client.httpclient.auth_tenant_id = mock.Mock()

        networks = self.neutron_api.get_all_admin_project_networks()

        self.assertEqual(fake_networks['networks'], networks)
        self.neutron_api.client.httpclient.auth_token.called
        self.neutron_api.client.httpclient.auth_tenant_id.called
        self.neutron_api.client.list_networks.assert_called_once_with(
            tenant_id=self.neutron_api.admin_project_id, shared=False)
