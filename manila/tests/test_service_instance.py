# Copyright (c) 2014 NetApp, Inc.
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

"""Unit tests for the instance module."""

import copy
import mock
import os

from manila import context
from manila import exception
from manila.share.drivers import service_instance
from manila import test
from manila.tests.db import fakes as db_fakes
from manila.tests import fake_compute
from manila.tests import fake_network

from oslo.config import cfg

CONF = cfg.CONF


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'share_network_id': 'fake share network id',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


class ServiceInstanceManagerTestCase(test.TestCase):
    """Tests InstanceManager."""

    def setUp(self):
        super(ServiceInstanceManagerTestCase, self).setUp()
        self._context = context.get_admin_context()

        self._helper_cifs = mock.Mock()
        self._helper_nfs = mock.Mock()
        self._db = mock.Mock()
        self.stubs.Set(service_instance.neutron, 'API', fake_network.API)
        self.stubs.Set(service_instance.compute, 'API', fake_compute.API)
        with mock.patch.object(service_instance.ServiceInstanceManager,
                               '_setup_connectivity_with_service_instances',
                               mock.Mock()):
            self._manager = service_instance.ServiceInstanceManager(self._db,
                                                                    {})
        self._manager.service_tenant_id = 'service tenant id'
        self._manager.service_network_id = 'service network id'
        self._manager.admin_context = self._context
        self._manager._execute = mock.Mock(return_value=('', ''))
        self._manager.vif_driver = mock.Mock()
        self.stubs.Set(service_instance, 'synchronized', mock.Mock(side_effect=
                                                                  lambda f: f))
        self.stubs.Set(service_instance.os.path, 'exists',
                       mock.Mock(return_value=True))
        self._manager._helpers = {
            'CIFS': self._helper_cifs,
            'NFS': self._helper_nfs,
        }
        self.share = fake_share()

    def test_get_service_network_net_exists(self):
        net1 = copy.copy(fake_network.API.network)
        net2 = copy.copy(fake_network.API.network)
        net1['name'] = CONF.service_network_name
        net1['id'] = 'fake service network id'
        self.stubs.Set(self._manager.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[net1, net2]))
        result = self._manager._get_service_network()
        self.assertEqual(result, net1['id'])

    def test_get_service_network_net_does_not_exists(self):
        net = fake_network.FakeNetwork()
        self.stubs.Set(self._manager.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[]))
        self.stubs.Set(self._manager.neutron_api, 'network_create',
                mock.Mock(return_value=net))
        result = self._manager._get_service_network()
        self.assertEqual(result, net['id'])

    def test_get_service_network_ambiguos(self):
        net = fake_network.FakeNetwork(name=CONF.service_network_name)
        self.stubs.Set(self._manager.neutron_api, 'get_all_tenant_networks',
                mock.Mock(return_value=[net, net]))
        self.assertRaises(exception.ManilaException,
                          self._manager._get_service_network)

    def test_get_service_instance_name(self):
        result = self._manager._get_service_instance_name(
                'fake_share_network_id')
        self.assertEqual(result, CONF.service_instance_name_template %
                'fake_share_network_id')

    def test_get_server_ip(self):
        fake_server = fake_compute.FakeServer(networks=
                {CONF.service_network_name: '10.254.0.1'})

        result = self._manager._get_server_ip(fake_server)

        self.assertEqual(result,
                fake_server['networks'][CONF.service_network_name][0])

    def test_get_server_ip_exception(self):
        fake_server = fake_compute.FakeServer(networks={})
        self.assertRaises(exception.ManilaException,
                          self._manager._get_server_ip, fake_server)

    def test_security_group_name_not_specified(self):
        self.stubs.Set(self._manager, 'get_config_option',
                       mock.Mock(return_value=None))
        result = self._manager._get_or_create_security_group(self._context)
        self.assertEqual(result, None)
        self._manager.get_config_option.assert_called_once_with(
            'service_instance_security_group')

    def test_security_group_name_from_config_and_sg_exist(self):
        fake_secgroup = fake_compute.FakeSecurityGroup(name="fake_sg_name")
        self.stubs.Set(self._manager, 'get_config_option',
                       mock.Mock(return_value="fake_sg_name"))
        self.stubs.Set(self._manager.compute_api, 'security_group_list',
                       mock.Mock(return_value=[fake_secgroup, ]))
        result = self._manager._get_or_create_security_group(self._context)
        self.assertEqual(result, fake_secgroup)
        self._manager.get_config_option.assert_has_calls([
            mock.call('service_instance_security_group'),
        ])
        self._manager.compute_api.security_group_list.assert_called_once_with(
            self._context)

    def test_security_group_creation_with_name_from_config(self):
        name = "fake_sg_name"
        desc = "fake_sg_description"
        fake_secgroup = fake_compute.FakeSecurityGroup(name=name,
                                                       description=desc)
        self.stubs.Set(self._manager, 'get_config_option',
                       mock.Mock(return_value=name))
        self.stubs.Set(self._manager.compute_api, 'security_group_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._manager.compute_api, 'security_group_create',
                       mock.Mock(return_value=fake_secgroup))
        self.stubs.Set(self._manager.compute_api, 'security_group_rule_create',
                       mock.Mock())
        result = self._manager._get_or_create_security_group(
            context=self._context,
            name=None,
            description=desc,
        )
        self.assertEqual(result, fake_secgroup)
        self._manager.compute_api.security_group_list.assert_called_once_with(
            self._context)
        self._manager.compute_api.security_group_create.\
            assert_called_once_with(self._context, name, desc)
        self._manager.get_config_option.assert_has_calls([
            mock.call('service_instance_security_group'),
        ])

    def test_security_group_creation_with_provided_name(self):
        name = "fake_sg_name"
        desc = "fake_sg_description"
        fake_secgroup = fake_compute.FakeSecurityGroup(name=name,
                                                       description=desc)
        self.stubs.Set(self._manager.compute_api, 'security_group_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._manager.compute_api, 'security_group_create',
                       mock.Mock(return_value=fake_secgroup))
        self.stubs.Set(self._manager.compute_api, 'security_group_rule_create',
                       mock.Mock())
        result = self._manager._get_or_create_security_group(
            context=self._context,
            name=name,
            description=desc,
        )
        self._manager.compute_api.security_group_list.assert_called_once_with(
            self._context)
        self._manager.compute_api.security_group_create.\
            assert_called_once_with(self._context, name, desc)
        self.assertEqual(result, fake_secgroup)

    def test_security_group_two_sg_in_list(self):
        name = "fake_name"
        fake_secgroup1 = fake_compute.FakeSecurityGroup(name=name)
        fake_secgroup2 = fake_compute.FakeSecurityGroup(name=name)
        self.stubs.Set(self._manager.compute_api, 'security_group_list',
                       mock.Mock(return_value=[fake_secgroup1,
                                               fake_secgroup2]))
        self.assertRaises(exception.ServiceInstanceException,
            self._manager._get_or_create_security_group,
            self._context,
            name,
        )
        self._manager.compute_api.security_group_list.assert_called_once_with(
            self._context)

    def test_set_up_service_instance(self):
        fake_server = {'id': 'fake',
                       'ip': '1.2.3.4',
                       'pk_path': 'path'}
        expected_details = fake_server.copy()
        expected_details['instance_id'] = expected_details.pop('id')
        expected_details['password'] = CONF.service_instance_password
        expected_details['username'] = CONF.service_instance_user
        self.stubs.Set(self._manager, '_get_server_ip',
                       mock.Mock(return_value='fake_ip'))
        self.stubs.Set(self._manager.compute_api, 'server_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._manager, '_create_service_instance',
                       mock.Mock(return_value=fake_server))

        result = self._manager.set_up_service_instance(
            self._context, share_server_id='fake_share_srv_id',
            share_network_id='fake_share_network_id', create=True)

        self._manager.compute_api.server_list.assert_called_once()
        self._manager._get_server_ip.assert_called_once()
        self._manager._create_service_instance.assert_called_once()
        self.assertEqual(result, expected_details)

    def test_ensure_server(self):
        server_details = {'instance_id': 'fake_inst_id',
                          'ip': '1.2.3.4'}
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._manager, '_check_server_availability',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._manager.compute_api, 'server_get',
                       mock.Mock(return_value=fake_server))
        result = self._manager.ensure_service_instance(self._context,
                                                       server_details)
        self._manager.compute_api.server_get.\
                    assert_called_once_with(self._context,
                                            server_details['instance_id'])
        self._manager._check_server_availability.\
                                assert_called_once_with(server_details)
        self.assertTrue(result)

    def test_ensure_server_not_exists(self):
        server_details = {'instance_id': 'fake_inst_id',
                          'ip': '1.2.3.4'}
        fake_server = fake_compute.FakeServer()
        self.stubs.Set(self._manager, '_check_server_availability',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._manager.compute_api, 'server_get',
                       mock.Mock(side_effect=exception.InstanceNotFound(
                           instance_id=server_details['instance_id'])))
        result = self._manager.ensure_service_instance(self._context,
                                                       server_details)
        self._manager.compute_api.server_get.\
                    assert_called_once_with(self._context,
                                            server_details['instance_id'])
        self.assertFalse(self._manager._check_server_availability.called)
        self.assertFalse(result)

    def test_ensure_server_exception(self):
        server_details = {'instance_id': 'fake_inst_id',
                          'ip': '1.2.3.4'}
        self.stubs.Set(self._manager, '_check_server_availability',
                       mock.Mock(return_value=True))
        self.stubs.Set(self._manager.compute_api, 'server_get',
                       mock.Mock(side_effect=exception.ManilaException))
        self.assertRaises(exception.ManilaException,
                          self._manager.ensure_service_instance,
                          self._context,
                          server_details)
        self._manager.compute_api.server_get.\
                    assert_called_once_with(self._context,
                                            server_details['instance_id'])
        self.assertFalse(self._manager._check_server_availability.called)

    def test_ensure_server_non_active(self):
        server_details = {'instance_id': 'fake_inst_id',
                          'ip': '1.2.3.4'}
        fake_server = fake_compute.FakeServer(status='ERROR')
        self.stubs.Set(self._manager.compute_api, 'server_get',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._manager, '_check_server_availability',
                       mock.Mock(return_value=True))
        result = self._manager.ensure_service_instance(self._context,
                                                       server_details)
        self.assertFalse(self._manager._check_server_availability.called)
        self.assertFalse(result)

    def test_get_key_create_new(self):
        fake_keypair = fake_compute.FakeKeypair(
            name=CONF.manila_service_keypair_name)
        self.stubs.Set(self._manager.compute_api, 'keypair_list',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._manager.compute_api, 'keypair_import',
                       mock.Mock(return_value=fake_keypair))

        result = self._manager._get_key(self._context)

        self.assertEqual(result,
                         (fake_keypair.name,
                          os.path.expanduser(CONF.path_to_private_key)))
        self._manager.compute_api.keypair_list.assert_called_once()
        self._manager.compute_api.keypair_import.assert_called_once()

    def test_get_key_exists(self):
        fake_keypair = fake_compute.FakeKeypair(
                                name=CONF.manila_service_keypair_name,
                                public_key='fake_public_key')
        self.stubs.Set(self._manager.compute_api, 'keypair_list',
                       mock.Mock(return_value=[fake_keypair]))
        self.stubs.Set(self._manager.compute_api, 'keypair_import',
                       mock.Mock(return_value=fake_keypair))
        self.stubs.Set(self._manager, '_execute',
                       mock.Mock(return_value=('fake_public_key', '')))

        result = self._manager._get_key(self._context)

        self._manager.compute_api.keypair_list.assert_called_once()
        self.assertFalse(self._manager.compute_api.keypair_import.called)
        self.assertEqual(result,
                         (fake_keypair.name,
                          os.path.expanduser(CONF.path_to_private_key)))

    def test_get_key_exists_recreate(self):
        fake_keypair = fake_compute.FakeKeypair(
                                name=CONF.manila_service_keypair_name,
                                public_key='fake_public_key1')
        self.stubs.Set(self._manager.compute_api, 'keypair_list',
                       mock.Mock(return_value=[fake_keypair]))
        self.stubs.Set(self._manager.compute_api, 'keypair_import',
                       mock.Mock(return_value=fake_keypair))
        self.stubs.Set(self._manager.compute_api, 'keypair_delete',
                       mock.Mock())
        self.stubs.Set(self._manager, '_execute',
                       mock.Mock(return_value=('fake_public_key2', '')))

        result = self._manager._get_key(self._context)

        self._manager.compute_api.keypair_list.assert_called_once()
        self._manager.compute_api.keypair_delete.assert_called_once()
        self._manager.compute_api.keypair_import.\
                assert_called_once_with(self._context, fake_keypair.name,
                                        'fake_public_key2')
        self.assertEqual(result,
                         (fake_keypair.name,
                          os.path.expanduser(CONF.path_to_private_key)))

    def test_get_service_image(self):
        fake_image1 = fake_compute.FakeImage(name=CONF.service_image_name)
        fake_image2 = fake_compute.FakeImage(name='another-image')
        self.stubs.Set(self._manager.compute_api, 'image_list',
                       mock.Mock(return_value=[fake_image1, fake_image2]))

        result = self._manager._get_service_image(self._context)

        self.assertEqual(result, fake_image1.id)

    def test_get_service_image_not_found(self):
        self.stubs.Set(self._manager.compute_api, 'image_list',
                       mock.Mock(return_value=[]))

        self.assertRaises(exception.ManilaException,
                          self._manager._get_service_image,
                          self._context)

    def test_get_service_image_ambiguous(self):
        fake_image = fake_compute.FakeImage(name=CONF.service_image_name)
        self.stubs.Set(self._manager.compute_api, 'image_list',
                       mock.Mock(return_value=[fake_image, fake_image]))

        self.assertRaises(exception.ManilaException,
                          self._manager._get_service_image,
                          self._context)

    def test_create_service_instance(self):
        fake_server = fake_compute.FakeServer()
        fake_port = fake_network.FakePort()
        fake_security_group = fake_compute.FakeSecurityGroup()
        fake_instance_name = 'fake_instance_name'
        sn_id = 'fake_sn_id'
        srv_id = 'fake_srv_id'
        self.stubs.Set(self._manager, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._manager, '_get_key',
                       mock.Mock(
                           return_value=('fake_key_name', 'fake_key_path')))
        self.stubs.Set(self._manager, '_setup_network_for_instance',
                       mock.Mock(return_value=fake_port))
        self.stubs.Set(self._manager,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock())
        self.stubs.Set(self._manager.compute_api, 'server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._manager, '_get_server_ip',
                       mock.Mock(return_value='fake_ip'))
        self.stubs.Set(self._manager, '_get_or_create_security_group',
                       mock.Mock(return_value=fake_security_group))
        self.stubs.Set(service_instance.socket, 'socket', mock.Mock())
        self.stubs.Set(self._manager, '_get_service_instance_name',
                       mock.Mock(return_value=fake_instance_name))
        result = self._manager._create_service_instance(self._context, sn_id,
                                                        srv_id)

        self._manager._get_service_image.assert_called_once()
        self._manager._get_key.assert_called_once()
        self._manager._setup_network_for_instance.assert_called_once()
        self._manager._setup_connectivity_with_service_instances.\
                assert_called_once()
        self._manager.compute_api.server_create.assert_called_once_with(
                self._context, name=fake_instance_name, image='fake_image_id',
                flavor=CONF.service_instance_flavor_id,
                key_name='fake_key_name', nics=[{'port-id': fake_port['id']}])
        service_instance.socket.socket.assert_called_once()
        self.assertEqual(result, fake_server)

    def test_create_service_instance_error(self):
        fake_server = fake_compute.FakeServer(status='ERROR')
        fake_port = fake_network.FakePort()
        fake_security_group = fake_compute.FakeSecurityGroup()
        self.stubs.Set(self._manager, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._manager, '_get_key',
                       mock.Mock(
                           return_value=('fake_key_name', 'fake_key_path')))
        self.stubs.Set(self._manager, '_get_or_create_security_group',
                       mock.Mock(return_value=fake_security_group))
        self.stubs.Set(self._manager, '_setup_network_for_instance',
                       mock.Mock(return_value=fake_port))
        self.stubs.Set(self._manager,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock())
        self.stubs.Set(self._manager.compute_api, 'server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._manager.compute_api, 'server_get',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(service_instance.socket, 'socket', mock.Mock())

        self.assertRaises(exception.ManilaException,
                          self._manager._create_service_instance,
                          self._context, self.share, None)

        self._manager.compute_api.server_create.assert_called_once()
        self.assertFalse(self._manager.compute_api.server_get.called)
        self.assertFalse(service_instance.socket.socket.called)

    def test_create_service_instance_failed_setup_connectivity(self):
        fake_server = fake_compute.FakeServer(status='ERROR')
        fake_port = fake_network.FakePort()
        fake_security_group = fake_compute.FakeSecurityGroup()
        self.stubs.Set(self._manager, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._manager, '_get_key',
                       mock.Mock(
                           return_value=('fake_key_name', 'fake_key_path')))
        self.stubs.Set(self._manager, '_get_or_create_security_group',
                       mock.Mock(return_value=fake_security_group))
        self.stubs.Set(self._manager, '_setup_network_for_instance',
                       mock.Mock(return_value=fake_port))
        self.stubs.Set(self._manager,
                       '_setup_connectivity_with_service_instances',
                       mock.Mock(side_effect=exception.ManilaException))
        self.stubs.Set(self._manager.neutron_api, 'delete_port', mock.Mock())
        self.stubs.Set(self._manager.compute_api, 'server_create',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(self._manager.compute_api, 'server_get',
                       mock.Mock(return_value=fake_server))
        self.stubs.Set(service_instance.socket, 'socket', mock.Mock())

        self.assertRaises(exception.ManilaException,
                          self._manager._create_service_instance,
                          self._context, self.share, None)

        self._manager.neutron_api.delete_port.\
                assert_called_once_with(fake_port['id'])
        self.assertFalse(self._manager.compute_api.server_create.called)
        self.assertFalse(self._manager.compute_api.server_get.called)
        self.assertFalse(service_instance.socket.socket.called)

    def test_create_service_instance_no_key_and_password(self):
        self.stubs.Set(self._manager, '_get_service_image',
                       mock.Mock(return_value='fake_image_id'))
        self.stubs.Set(self._manager, '_get_key',
                       mock.Mock(return_value=(None, None)))
        self.assertRaises(exception.ManilaException,
                          self._manager._create_service_instance,
                          self._context, self.share, None)

    def test_setup_network_for_instance(self):
        fake_service_net = fake_network.FakeNetwork(subnets=[])
        fake_service_subnet = fake_network.\
                FakeSubnet(name=self.share['share_network_id'])
        fake_router = fake_network.FakeRouter()
        fake_port = fake_network.FakePort()
        self.stubs.Set(self._manager.neutron_api, 'get_network',
                mock.Mock(return_value=fake_service_net))
        self.stubs.Set(self._manager.neutron_api, 'subnet_create',
                mock.Mock(return_value=fake_service_subnet))
        self.stubs.Set(self._manager.db, 'share_network_get',
                mock.Mock(return_value='fake_share_network'))
        self.stubs.Set(self._manager, '_get_private_router',
                mock.Mock(return_value=fake_router))
        self.stubs.Set(self._manager.neutron_api, 'router_add_interface',
                mock.Mock())
        self.stubs.Set(self._manager.neutron_api, 'create_port',
                mock.Mock(return_value=fake_port))
        self.stubs.Set(self._manager, '_get_cidr_for_subnet',
                mock.Mock(return_value='fake_cidr'))

        result = self._manager._setup_network_for_instance('fake_share_net')

        self._manager.neutron_api.get_network.\
                assert_called_once_with(self._manager.service_network_id)
        self._manager._get_private_router.\
                assert_called_once_with('fake_share_net')
        self._manager.neutron_api.router_add_interface.\
                assert_called_once_with('fake_router_id', 'fake_subnet_id')
        self._manager.neutron_api.subnet_create.assert_called_once_with(
                                         self._manager.service_tenant_id,
                                         self._manager.service_network_id,
                                         'fake_share_net',
                                         'fake_cidr')
        self._manager.neutron_api.create_port.assert_called_once_with(
                                         self._manager.service_tenant_id,
                                         self._manager.service_network_id,
                                         subnet_id='fake_subnet_id',
                                         device_owner='manila')
        self._manager._get_cidr_for_subnet.assert_called_once()
        self.assertEqual(result, fake_port)

    def test_get_private_router(self):
        fake_net = fake_network.FakeNetwork()
        fake_subnet = fake_network.FakeSubnet(gateway_ip='fake_ip')
        fake_share_network = {'neutron_net_id': fake_net['id'],
                              'neutron_subnet_id': fake_subnet['id']}
        self.stubs.Set(self._manager.db, 'share_network_get',
                mock.Mock(return_value=fake_share_network))
        fake_port = fake_network.FakePort(fixed_ips=[
                        {'subnet_id': fake_subnet['id'],
                         'ip_address': fake_subnet['gateway_ip']}],
                        device_id='fake_router_id')
        fake_router = fake_network.FakeRouter(id='fake_router_id')
        self.stubs.Set(self._manager.neutron_api, 'get_subnet',
                mock.Mock(return_value=fake_subnet))
        self.stubs.Set(self._manager.neutron_api, 'list_ports',
                mock.Mock(return_value=[fake_port]))
        self.stubs.Set(self._manager.neutron_api, 'show_router',
                mock.Mock(return_value=fake_router))

        result = self._manager._get_private_router(
                    {'neutron_subnet_id': fake_subnet['id'],
                     'neutron_net_id': fake_net['id']})

        self._manager.neutron_api.get_subnet.\
                assert_called_once_with(fake_subnet['id'])
        self._manager.neutron_api.list_ports.\
                assert_called_once_with(network_id=fake_net['id'])
        self._manager.neutron_api.show_router.\
                assert_called_once_with(fake_router['id'])
        self.assertEqual(result, fake_router)

    def test_get_private_router_exception(self):
        fake_net = fake_network.FakeNetwork()
        fake_subnet = fake_network.FakeSubnet(gateway_ip='fake_ip')
        fake_share_network = {'neutron_net_id': fake_net['id'],
                              'neutron_subnet_id': fake_subnet['id']}
        self.stubs.Set(self._manager.db, 'share_network_get',
                mock.Mock(return_value=fake_share_network))
        self.stubs.Set(self._manager.neutron_api, 'get_subnet',
                mock.Mock(return_value=fake_subnet))
        self.stubs.Set(self._manager.neutron_api, 'list_ports',
                mock.Mock(return_value=[]))

        self.assertRaises(exception.ManilaException,
                self._manager._get_private_router,
                {'neutron_subnet_id': fake_subnet['id'],
                 'neutron_net_id': fake_net['id']})

    def test_setup_connectivity_with_service_instances(self):
        fake_subnet = fake_network.FakeSubnet(cidr='10.254.0.0/29')
        fake_port = fake_network.FakePort(fixed_ips=[
            {'subnet_id': fake_subnet['id'], 'ip_address': '10.254.0.2'}],
            mac_address='fake_mac_address')

        self.stubs.Set(self._manager, '_get_service_port',
                mock.Mock(return_value=fake_port))
        self.stubs.Set(self._manager.vif_driver, 'get_device_name',
                mock.Mock(return_value='fake_interface_name'))
        self.stubs.Set(self._manager.neutron_api, 'get_subnet',
                mock.Mock(return_value=fake_subnet))
        self.stubs.Set(self._manager, '_remove_outdated_interfaces',
                       mock.Mock())
        self.stubs.Set(self._manager.vif_driver, 'plug', mock.Mock())
        device_mock = mock.Mock()
        self.stubs.Set(service_instance.ip_lib, 'IPDevice',
                       mock.Mock(return_value=device_mock))

        self._manager._setup_connectivity_with_service_instances()

        self._manager._get_service_port.assert_called_once()
        self._manager.vif_driver.get_device_name.assert_called_once_with(
                fake_port)
        self._manager.vif_driver.plug.assert_called_once_with(fake_port['id'],
                'fake_interface_name', fake_port['mac_address'])
        self._manager.neutron_api.get_subnet.assert_called_once_with(
                fake_subnet['id'])
        self._manager.vif_driver.init_l3.assert_called_once()
        service_instance.ip_lib.IPDevice.assert_called_once()
        device_mock.route.pullup_route.assert_called_once()
        self._manager._remove_outdated_interfaces.assert_called_once_with(
                device_mock)

    def test_get_service_port(self):
        fake_service_port = fake_network.FakePort(device_id='manila-share')
        fake_service_net = fake_network.FakeNetwork(subnets=[])
        self.stubs.Set(self._manager.neutron_api, 'list_ports',
                       mock.Mock(return_value=[]))
        self.stubs.Set(self._manager, '_execute',
                       mock.Mock(return_value=('fake_host', '')))
        self.stubs.Set(self._manager.neutron_api, 'create_port',
                       mock.Mock(return_value=fake_service_port))
        self.stubs.Set(self._manager.neutron_api, 'get_network',
                       mock.Mock(return_value=fake_service_net))
        self.stubs.Set(self._manager.neutron_api, 'update_port_fixed_ips',
                       mock.Mock(return_value=fake_service_port))

        result = self._manager._get_service_port()

        self._manager.neutron_api.list_ports.\
                            assert_called_once_with(device_id='manila-share')
        self._manager.db.service_get_all_by_topic.assert_called_once()
        self._manager.neutron_api.create_port.assert_called_once_with(
                                    self._manager.service_tenant_id,
                                    self._manager.service_network_id,
                                    device_id='manila-share',
                                    device_owner='manila:share',
                                    host_id='fake_host'
                                    )
        self._manager.neutron_api.get_network.assert_called_once()
        self.assertFalse(self._manager.neutron_api.
                                                update_port_fixed_ips.called)
        self.assertEqual(result, fake_service_port)

    def test_get_service_port_ambigious_ports(self):
        fake_service_port = fake_network.FakePort(device_id='manila-share')
        self.stubs.Set(self._manager.neutron_api, 'list_ports',
                mock.Mock(return_value=[fake_service_port, fake_service_port]))
        self.assertRaises(exception.ManilaException,
                          self._manager._get_service_port)

    def test_get_service_port_exists(self):
        fake_service_port = fake_network.FakePort(device_id='manila-share')
        fake_service_net = fake_network.FakeNetwork(subnets=[])
        self.stubs.Set(self._manager.neutron_api, 'list_ports',
                       mock.Mock(return_value=[fake_service_port]))
        self.stubs.Set(self._manager.db, 'service_get_all_by_topic',
                mock.Mock(return_value=[{'host': 'fake_host'}]))
        self.stubs.Set(self._manager.neutron_api, 'create_port',
                       mock.Mock(return_value=fake_service_port))
        self.stubs.Set(self._manager.neutron_api, 'get_network',
                       mock.Mock(return_value=fake_service_net))
        self.stubs.Set(self._manager.neutron_api, 'update_port_fixed_ips',
                       mock.Mock(return_value=fake_service_port))

        result = self._manager._get_service_port()

        self._manager.neutron_api.list_ports.assert_called_once_with(
                device_id='manila-share')
        self.assertFalse(self._manager.db.service_get_all_by_topic.called)
        self.assertFalse(self._manager.neutron_api.create_port.called)
        self._manager.neutron_api.get_network.assert_called_once()
        self.assertFalse(self._manager.neutron_api.
                                        update_port_fixed_ips.called)
        self.assertEqual(result, fake_service_port)

    def test_get_cidr_for_subnet(self):
        serv_cidr = service_instance.netaddr.IPNetwork(
                CONF.service_network_cidr)
        cidrs = serv_cidr.subnet(29)
        cidr1 = str(cidrs.next())
        cidr2 = str(cidrs.next())
        self.stubs.Set(self._manager, '_get_all_service_subnets',
                       mock.Mock(return_value=[]))
        result = self._manager._get_cidr_for_subnet()
        self.assertEqual(result, cidr1)

        fake_subnet = fake_network.FakeSubnet(cidr=cidr1)
        self.stubs.Set(self._manager, '_get_all_service_subnets',
                       mock.Mock(return_value=[fake_subnet]))
        result = self._manager._get_cidr_for_subnet()
        self.assertEqual(result, cidr2)

    def test_delete_service_instance(self):
        fake_server = fake_compute.FakeServer()
        fake_router = fake_network.FakeRouter()
        fake_subnet = fake_network.FakeSubnet(cidr='10.254.0.0/29')
        self.stubs.Set(self._manager, '_delete_server', mock.Mock())
        self.stubs.Set(self._manager, '_get_service_subnet',
                mock.Mock(return_value=fake_subnet))
        self.stubs.Set(self._manager, '_get_private_router',
                mock.Mock(return_value=fake_router))
        self.stubs.Set(self._manager.neutron_api, 'router_remove_interface',
                mock.Mock())
        self.stubs.Set(self._manager.neutron_api, 'update_subnet',
                mock.Mock())
        self._manager._delete_server.assert_called_once()
        self._manager._get_service_subnet.assert_called_once()
        self._manager._get_private_router.assert_called_once()
        self._manager.neutron_api.router_remove_interface.assert_called_once()
        self._manager.neutron_api.update_subnet.assert_called_once()
