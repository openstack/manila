# Copyright (c) 2014 NetApp, Inc.
# Copyright (c) 2015 Mirantis, Inc.
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

import os
import time

import ddt
import mock
import netaddr
from oslo_config import cfg
from oslo_utils import importutils
import six

from manila import exception
from manila.share import configuration
from manila.share import driver  # noqa
from manila.share.drivers import service_instance
from manila import test
from manila.tests import fake_compute
from manila.tests import fake_network
from manila.tests import utils as test_utils

CONF = cfg.CONF


def fake_get_config_option(key):
    if key == 'driver_handles_share_servers':
        return True
    elif key == 'service_instance_password':
        return None
    elif key == 'service_instance_user':
        return 'fake_user'
    elif key == 'service_network_name':
        return 'fake_service_network_name'
    elif key == 'service_instance_flavor_id':
        return 100
    elif key == 'service_instance_name_template':
        return 'fake_manila_service_instance_%s'
    elif key == 'service_image_name':
        return 'fake_service_image_name'
    elif key == 'manila_service_keypair_name':
        return 'fake_manila_service_keypair_name'
    elif key == 'path_to_private_key':
        return 'fake_path_to_private_key'
    elif key == 'path_to_public_key':
        return 'fake_path_to_public_key'
    elif key == 'max_time_to_build_instance':
        return 500
    elif key == 'connect_share_server_to_tenant_network':
        return False
    elif key == 'service_network_cidr':
        return '99.254.0.0/24'
    elif key == 'service_network_division_mask':
        return 27
    elif key == 'service_instance_network_helper_type':
        return service_instance.NEUTRON_NAME
    elif key == 'service_network_name':
        return 'fake_service_network_name'
    elif key == 'interface_driver':
        return 'i.am.fake.VifDriver'
    else:
        return mock.Mock()


class FakeServiceInstance(object):

    def __init__(self, driver_config=None):
        super(FakeServiceInstance, self).__init__()
        self.compute_api = service_instance.compute.API()
        self.admin_context = service_instance.context.get_admin_context()
        self.driver_config = driver_config

    def get_config_option(self, key):
        return fake_get_config_option(key)


class FakeNetworkHelper(service_instance.BaseNetworkhelper):

    @property
    def NAME(self):
        return self.get_config_option("service_instance_network_helper_type")

    def __init__(self, service_instance_manager):
        self.get_config_option = service_instance_manager.get_config_option

    def get_network_name(self, network_info):
        """Return name of network."""
        return 'fake_network_name'

    def setup_connectivity_with_service_instances(self):
        """Nothing to do in fake network helper."""

    def setup_network(self, network_info):
        """Combine fake network data."""
        return dict()

    def teardown_network(self, server_details):
        """Nothing to do in fake network helper."""


@ddt.ddt
class ServiceInstanceManagerTestCase(test.TestCase):
    """Test suite for service instance manager."""

    def setUp(self):
        super(ServiceInstanceManagerTestCase, self).setUp()
        self.instance_id = 'fake_instance_id'
        self.config = configuration.Configuration(None)
        self.config.safe_get = mock.Mock(side_effect=fake_get_config_option)
        self.mock_object(service_instance.compute, 'API', fake_compute.API)
        self.mock_object(
            service_instance.os.path, 'exists', mock.Mock(return_value=True))
        self.mock_object(service_instance, 'NeutronNetworkHelper',
                         mock.Mock(side_effect=FakeNetworkHelper))
        self.mock_object(service_instance, 'NovaNetworkHelper',
                         mock.Mock(side_effect=FakeNetworkHelper))
        self._manager = service_instance.ServiceInstanceManager(self.config)
        self._manager._execute = mock.Mock(return_value=('', ''))
        self.mock_object(time, 'sleep')

    def test_get_config_option_from_driver_config(self):
        username1 = 'fake_username_1_%s' % self.id()
        username2 = 'fake_username_2_%s' % self.id()
        config_data = dict(
            DEFAULT=dict(service_instance_user=username1),
            CUSTOM=dict(service_instance_user=username2))
        with test_utils.create_temp_config_with_opts(config_data):
            self.config = configuration.Configuration(
                service_instance.common_opts, config_group='CUSTOM')
            self._manager = service_instance.ServiceInstanceManager(
                self.config)
        result = self._manager.get_config_option('service_instance_user')
        self.assertEqual(username2, result)

    def test_get_config_option_from_common_config(self):
        username = 'fake_username_%s' % self.id()
        config_data = dict(DEFAULT=dict(service_instance_user=username))
        with test_utils.create_temp_config_with_opts(config_data):
            self._manager = service_instance.ServiceInstanceManager()
        result = self._manager.get_config_option('service_instance_user')
        self.assertEqual(username, result)

    def test_get_nova_network_helper(self):
        # Mock it again, because one of these was called in setUp method.
        self.mock_object(service_instance, 'NeutronNetworkHelper')
        self.mock_object(service_instance, 'NovaNetworkHelper')
        config_data = dict(DEFAULT=dict(
            service_instance_user='fake_username',
            driver_handles_share_servers=True,
            service_instance_network_helper_type=service_instance.NOVA_NAME))
        with test_utils.create_temp_config_with_opts(config_data):
            self._manager = service_instance.ServiceInstanceManager()
            self._manager.network_helper
        service_instance.NovaNetworkHelper.assert_called_once_with(
            self._manager)
        self.assertFalse(service_instance.NeutronNetworkHelper.called)

    def test_get_neutron_network_helper(self):
        # Mock it again, because one of these was called in setUp method.
        self.mock_object(service_instance, 'NeutronNetworkHelper')
        self.mock_object(service_instance, 'NovaNetworkHelper')
        config_data = dict(DEFAULT=dict(
            service_instance_user='fake_username',
            driver_handles_share_servers=True,
            service_instance_network_helper_type=service_instance.NEUTRON_NAME)
        )
        with test_utils.create_temp_config_with_opts(config_data):
            self._manager = service_instance.ServiceInstanceManager()
            self._manager.network_helper
        service_instance.NeutronNetworkHelper.assert_called_once_with(
            self._manager)
        self.assertFalse(service_instance.NovaNetworkHelper.called)

    @ddt.data(
        None, '', 'fake', service_instance.NOVA_NAME + '_as_prefix',
        service_instance.NEUTRON_NAME + '_as_prefix',
        'as_suffix_' + service_instance.NOVA_NAME,
        'as_suffix_' + service_instance.NEUTRON_NAME)
    def test_get_fake_network_helper(self, value):
        # Mock it again, because one of these was called in setUp method.
        self.mock_object(service_instance, 'NeutronNetworkHelper')
        self.mock_object(service_instance, 'NovaNetworkHelper')
        config_data = dict(DEFAULT=dict(
            service_instance_user='fake_username',
            driver_handles_share_servers=True,
            service_instance_network_helper_type=value))
        with test_utils.create_temp_config_with_opts(config_data):
            manager = service_instance.ServiceInstanceManager()
            self.assertRaises(exception.ManilaException,
                              lambda: manager.network_helper)
        self.assertFalse(service_instance.NeutronNetworkHelper.called)
        self.assertFalse(service_instance.NovaNetworkHelper.called)

    def test_init_with_driver_config_and_handling_of_share_servers(self):
        self.mock_object(service_instance, 'NeutronNetworkHelper')
        self.mock_object(service_instance, 'NovaNetworkHelper')
        config_data = dict(CUSTOM=dict(
            driver_handles_share_servers=True,
            service_instance_user='fake_user',
            service_instance_network_helper_type=service_instance.NOVA_NAME))
        opts = service_instance.common_opts + driver.share_opts
        with test_utils.create_temp_config_with_opts(config_data):
            self.config = configuration.Configuration(opts, 'CUSTOM')
            self._manager = service_instance.ServiceInstanceManager(
                self.config)
        self.assertEqual(
            True,
            self._manager.get_config_option("driver_handles_share_servers"))
        self.assertNotEqual(None, self._manager.driver_config)
        self.assertTrue(hasattr(self._manager, 'network_helper'))
        self.assertTrue(service_instance.NovaNetworkHelper.called)
        self.assertFalse(service_instance.NeutronNetworkHelper.called)

    def test_init_with_driver_config_and_wo_handling_of_share_servers(self):
        self.mock_object(service_instance, 'NeutronNetworkHelper')
        self.mock_object(service_instance, 'NovaNetworkHelper')
        config_data = dict(CUSTOM=dict(
            driver_handles_share_servers=False,
            service_instance_user='fake_user'))
        opts = service_instance.common_opts + driver.share_opts
        with test_utils.create_temp_config_with_opts(config_data):
            self.config = configuration.Configuration(opts, 'CUSTOM')
            self._manager = service_instance.ServiceInstanceManager(
                self.config)
        self.assertNotEqual(None, self._manager.driver_config)
        self.assertFalse(hasattr(self._manager, 'network_helper'))
        self.assertFalse(service_instance.NovaNetworkHelper.called)
        self.assertFalse(service_instance.NeutronNetworkHelper.called)

    def test_init_with_common_config_and_handling_of_share_servers(self):
        self.mock_object(service_instance, 'NeutronNetworkHelper')
        self.mock_object(service_instance, 'NovaNetworkHelper')
        config_data = dict(DEFAULT=dict(
            service_instance_user='fake_username',
            driver_handles_share_servers=True,
            service_instance_network_helper_type=service_instance.NOVA_NAME))
        with test_utils.create_temp_config_with_opts(config_data):
            self._manager = service_instance.ServiceInstanceManager()
        self.assertEqual(
            True,
            self._manager.get_config_option("driver_handles_share_servers"))
        self.assertIsNone(self._manager.driver_config)
        self.assertTrue(hasattr(self._manager, 'network_helper'))
        self.assertTrue(service_instance.NovaNetworkHelper.called)
        self.assertFalse(service_instance.NeutronNetworkHelper.called)

    def test_init_with_common_config_and_wo_handling_of_share_servers(self):
        self.mock_object(service_instance, 'NeutronNetworkHelper')
        self.mock_object(service_instance, 'NovaNetworkHelper')
        config_data = dict(DEFAULT=dict(
            service_instance_user='fake_username',
            driver_handles_share_servers=False))
        with test_utils.create_temp_config_with_opts(config_data):
            self._manager = service_instance.ServiceInstanceManager()
        self.assertEqual(
            False,
            self._manager.get_config_option("driver_handles_share_servers"))
        self.assertIsNone(self._manager.driver_config)
        self.assertFalse(hasattr(self._manager, 'network_helper'))
        self.assertFalse(service_instance.NovaNetworkHelper.called)
        self.assertFalse(service_instance.NeutronNetworkHelper.called)

    def test_no_service_user_defined(self):
        group_name = 'GROUP_%s' % self.id()
        config_data = {group_name: dict()}
        with test_utils.create_temp_config_with_opts(config_data):
            config = configuration.Configuration(
                service_instance.common_opts, config_group=group_name)
        self.assertRaises(
            exception.ServiceInstanceException,
            service_instance.ServiceInstanceManager, config)

    def test_get_service_instance_name_using_driver_config(self):
        fake_server_id = 'fake_share_server_id_%s' % self.id()
        self.mock_object(service_instance, 'NeutronNetworkHelper')
        self.mock_object(service_instance, 'NovaNetworkHelper')
        config_data = dict(CUSTOM=dict(
            driver_handles_share_servers=True,
            service_instance_user='fake_user',
            service_instance_network_helper_type=service_instance.NOVA_NAME))
        opts = service_instance.common_opts + driver.share_opts
        with test_utils.create_temp_config_with_opts(config_data):
            self.config = configuration.Configuration(opts, 'CUSTOM')
            self._manager = service_instance.ServiceInstanceManager(
                self.config)
        result = self._manager._get_service_instance_name(fake_server_id)
        self.assertNotEqual(None, self._manager.driver_config)
        self.assertEqual(
            self._manager.get_config_option(
                "service_instance_name_template") % "%s_%s" % (
                    self._manager.driver_config.config_group, fake_server_id),
            result)
        self.assertEqual(
            True,
            self._manager.get_config_option("driver_handles_share_servers"))
        self.assertTrue(hasattr(self._manager, 'network_helper'))
        self.assertTrue(service_instance.NovaNetworkHelper.called)
        self.assertFalse(service_instance.NeutronNetworkHelper.called)

    def test_get_service_instance_name_using_default_config(self):
        fake_server_id = 'fake_share_server_id_%s' % self.id()
        config_data = dict(CUSTOM=dict(
            service_instance_user='fake_user',
            service_instance_network_helper_type=service_instance.NOVA_NAME))
        with test_utils.create_temp_config_with_opts(config_data):
            self._manager = service_instance.ServiceInstanceManager()
        result = self._manager._get_service_instance_name(fake_server_id)
        self.assertIsNone(self._manager.driver_config)
        self.assertEqual(
            self._manager.get_config_option(
                "service_instance_name_template") % fake_server_id, result)

    def test__check_server_availability_available_from_start(self):
        fake_server = dict(id='fake_server', ip='127.0.0.1')
        self.mock_object(service_instance.socket.socket, 'connect')
        self.mock_object(service_instance.time, 'sleep')
        self.mock_object(service_instance.time, 'time',
                         mock.Mock(return_value=0))

        result = self._manager._check_server_availability(fake_server)

        self.assertTrue(result)
        service_instance.socket.socket.connect.assert_called_once_with(
            (fake_server['ip'], 22))
        service_instance.time.time.assert_has_calls([
            mock.call(), mock.call()])
        service_instance.time.time.assert_has_calls([])

    @ddt.data(True, False)
    def test__check_server_availability_with_recall(self, is_ok):
        fake_server = dict(id='fake_server', ip='fake_ip_address')

        self.fake_time = 0

        def fake_connect(addr):
            if not(is_ok and self.fake_time > 1):
                raise service_instance.socket.error

        def fake_time():
            return self.fake_time

        def fake_sleep(time):
            self.fake_time += 5

        self.mock_object(service_instance.time, 'sleep',
                         mock.Mock(side_effect=fake_sleep))
        self.mock_object(service_instance.socket.socket, 'connect',
                         mock.Mock(side_effect=fake_connect))
        self.mock_object(service_instance.time, 'time',
                         mock.Mock(side_effect=fake_time))
        self._manager.max_time_to_build_instance = 6

        result = self._manager._check_server_availability(fake_server)

        if is_ok:
            self.assertTrue(result)
        else:
            self.assertFalse(result)
        service_instance.socket.socket.connect.assert_has_calls([
            mock.call((fake_server['ip'], 22)),
            mock.call((fake_server['ip'], 22))])
        service_instance.time.time.assert_has_calls([
            mock.call(), mock.call(), mock.call()])
        service_instance.time.time.assert_has_calls([mock.call()])

    def test_get_server_ip_found_in_networks_section(self):
        ip = '10.0.0.1'
        net_name = self._manager.get_config_option('service_network_name')
        fake_server = dict(networks={net_name: [ip]})
        result = self._manager._get_server_ip(fake_server, net_name)
        self.assertEqual(ip, result)

    def test_get_server_ip_found_in_addresses_section(self):
        ip = '10.0.0.1'
        net_name = self._manager.get_config_option('service_network_name')
        fake_server = dict(addresses={net_name: [dict(addr=ip, version=4)]})
        result = self._manager._get_server_ip(fake_server, net_name)
        self.assertEqual(ip, result)

    @ddt.data(
        {},
        {'networks': {fake_get_config_option('service_network_name'): []}},
        {'addresses': {fake_get_config_option('service_network_name'): []}})
    def test_get_server_ip_not_found(self, data):
        self.assertRaises(
            exception.ManilaException,
            self._manager._get_server_ip, data,
            fake_get_config_option('service_network_name'))

    def test_security_group_name_not_specified(self):
        self.mock_object(self._manager, 'get_config_option',
                         mock.Mock(return_value=None))
        result = self._manager._get_or_create_security_group(
            self._manager.admin_context)
        self.assertIsNone(result)
        self._manager.get_config_option.assert_called_once_with(
            'service_instance_security_group')

    def test_security_group_name_from_config_and_sg_exist(self):
        fake_secgroup = fake_compute.FakeSecurityGroup(name="fake_sg_name")
        self.mock_object(self._manager, 'get_config_option',
                         mock.Mock(return_value="fake_sg_name"))
        self.mock_object(self._manager.compute_api, 'security_group_list',
                         mock.Mock(return_value=[fake_secgroup, ]))
        result = self._manager._get_or_create_security_group(
            self._manager.admin_context)
        self.assertEqual(fake_secgroup, result)
        self._manager.get_config_option.assert_has_calls([
            mock.call('service_instance_security_group'),
        ])
        self._manager.compute_api.security_group_list.assert_called_once_with(
            self._manager.admin_context)

    def test_security_group_creation_with_name_from_config(self):
        name = "fake_sg_name"
        desc = "fake_sg_description"
        fake_secgroup = fake_compute.FakeSecurityGroup(name=name,
                                                       description=desc)
        self.mock_object(self._manager, 'get_config_option',
                         mock.Mock(return_value=name))
        self.mock_object(self._manager.compute_api, 'security_group_list',
                         mock.Mock(return_value=[]))
        self.mock_object(self._manager.compute_api, 'security_group_create',
                         mock.Mock(return_value=fake_secgroup))
        self.mock_object(self._manager.compute_api,
                         'security_group_rule_create')
        result = self._manager._get_or_create_security_group(
            context=self._manager.admin_context,
            name=None,
            description=desc,
        )
        self.assertEqual(fake_secgroup, result)
        self._manager.compute_api.security_group_list.assert_called_once_with(
            self._manager.admin_context)
        self._manager.compute_api.security_group_create.\
            assert_called_once_with(self._manager.admin_context, name, desc)
        self._manager.get_config_option.assert_has_calls([
            mock.call('service_instance_security_group'),
        ])

    def test_security_group_creation_with_provided_name(self):
        name = "fake_sg_name"
        fake_secgroup = fake_compute.FakeSecurityGroup(name=name)
        self.mock_object(self._manager.compute_api, 'security_group_list',
                         mock.Mock(return_value=[]))
        self.mock_object(self._manager.compute_api, 'security_group_create',
                         mock.Mock(return_value=fake_secgroup))
        self.mock_object(self._manager.compute_api,
                         'security_group_rule_create')
        result = self._manager._get_or_create_security_group(
            context=self._manager.admin_context, name=name)
        self._manager.compute_api.security_group_list.assert_called_once_with(
            self._manager.admin_context)
        self._manager.compute_api.security_group_create.\
            assert_called_once_with(
                self._manager.admin_context, name, mock.ANY)
        self.assertEqual(fake_secgroup, result)

    def test_security_group_two_sg_in_list(self):
        name = "fake_name"
        fake_secgroup1 = fake_compute.FakeSecurityGroup(name=name)
        fake_secgroup2 = fake_compute.FakeSecurityGroup(name=name)
        self.mock_object(self._manager.compute_api, 'security_group_list',
                         mock.Mock(return_value=[fake_secgroup1,
                                                 fake_secgroup2]))
        self.assertRaises(exception.ServiceInstanceException,
                          self._manager._get_or_create_security_group,
                          self._manager.admin_context,
                          name)
        self._manager.compute_api.security_group_list.assert_called_once_with(
            self._manager.admin_context)

    @ddt.data(
        dict(),
        dict(service_port_id='fake_service_port_id'),
        dict(public_port_id='fake_public_port_id'),
        dict(service_port_id='fake_service_port_id',
             public_port_id='fake_public_port_id'),
    )
    def test_set_up_service_instance(self, update_data):
        fake_network_info = dict(foo='bar', server_id='fake_server_id',
                                 service_ip='fake_ip')
        fake_server = dict(
            id='fake', ip='1.2.3.4', public_address='1.2.3.4', pk_path=None,
            subnet_id='fake-subnet-id', router_id='fake-router-id',
            username=self._manager.get_config_option('service_instance_user'),
            service_ip='fake_ip')
        fake_server.update(update_data)
        expected_details = fake_server.copy()
        expected_details.pop('pk_path')
        expected_details['instance_id'] = expected_details.pop('id')
        self.mock_object(self._manager, '_create_service_instance',
                         mock.Mock(return_value=fake_server))
        self.mock_object(self._manager, '_check_server_availability')

        result = self._manager.set_up_service_instance(
            self._manager.admin_context, fake_network_info)

        self._manager._create_service_instance.assert_called_once_with(
            self._manager.admin_context,
            fake_network_info['server_id'], fake_network_info)
        self._manager._check_server_availability.assert_called_once_with(
            expected_details)
        self.assertEqual(expected_details, result)

    def test_set_up_service_instance_not_available(self):
        fake_network_info = dict(foo='bar', server_id='fake_server_id',
                                 service_ip='fake_ip')
        fake_server = dict(
            id='fake', ip='1.2.3.4', public_address='1.2.3.4', pk_path=None,
            subnet_id='fake-subnet-id', router_id='fake-router-id',
            username=self._manager.get_config_option('service_instance_user'),
            service_ip='fake_ip')
        expected_details = fake_server.copy()
        expected_details.pop('pk_path')
        expected_details['instance_id'] = expected_details.pop('id')
        self.mock_object(self._manager, '_create_service_instance',
                         mock.Mock(return_value=fake_server))
        self.mock_object(self._manager, '_check_server_availability',
                         mock.Mock(return_value=False))

        self.assertRaises(
            exception.ServiceInstanceException,
            self._manager.set_up_service_instance,
            self._manager.admin_context, fake_network_info)

        self._manager._create_service_instance.assert_called_once_with(
            self._manager.admin_context,
            fake_network_info['server_id'], fake_network_info)
        self._manager._check_server_availability.assert_called_once_with(
            expected_details)

    def test_ensure_server(self):
        server_details = {'instance_id': 'fake_inst_id', 'ip': '1.2.3.4'}
        fake_server = fake_compute.FakeServer()
        self.mock_object(self._manager, '_check_server_availability',
                         mock.Mock(return_value=True))
        self.mock_object(self._manager.compute_api, 'server_get',
                         mock.Mock(return_value=fake_server))
        result = self._manager.ensure_service_instance(
            self._manager.admin_context, server_details)
        self._manager.compute_api.server_get.assert_called_once_with(
            self._manager.admin_context, server_details['instance_id'])
        self._manager._check_server_availability.assert_called_once_with(
            server_details)
        self.assertTrue(result)

    def test_ensure_server_not_exists(self):
        server_details = {'instance_id': 'fake_inst_id', 'ip': '1.2.3.4'}
        self.mock_object(self._manager, '_check_server_availability',
                         mock.Mock(return_value=True))
        self.mock_object(self._manager.compute_api, 'server_get',
                         mock.Mock(side_effect=exception.InstanceNotFound(
                             instance_id=server_details['instance_id'])))
        result = self._manager.ensure_service_instance(
            self._manager.admin_context, server_details)
        self._manager.compute_api.server_get.assert_called_once_with(
            self._manager.admin_context, server_details['instance_id'])
        self.assertFalse(self._manager._check_server_availability.called)
        self.assertFalse(result)

    def test_ensure_server_exception(self):
        server_details = {'instance_id': 'fake_inst_id', 'ip': '1.2.3.4'}
        self.mock_object(self._manager, '_check_server_availability',
                         mock.Mock(return_value=True))
        self.mock_object(self._manager.compute_api, 'server_get',
                         mock.Mock(side_effect=exception.ManilaException))
        self.assertRaises(exception.ManilaException,
                          self._manager.ensure_service_instance,
                          self._manager.admin_context,
                          server_details)
        self._manager.compute_api.server_get.assert_called_once_with(
            self._manager.admin_context, server_details['instance_id'])
        self.assertFalse(self._manager._check_server_availability.called)

    def test_ensure_server_non_active(self):
        server_details = {'instance_id': 'fake_inst_id', 'ip': '1.2.3.4'}
        fake_server = fake_compute.FakeServer(status='ERROR')
        self.mock_object(self._manager.compute_api, 'server_get',
                         mock.Mock(return_value=fake_server))
        self.mock_object(self._manager, '_check_server_availability',
                         mock.Mock(return_value=True))
        result = self._manager.ensure_service_instance(
            self._manager.admin_context, server_details)
        self.assertFalse(self._manager._check_server_availability.called)
        self.assertFalse(result)

    def test_get_key_create_new(self):
        keypair_name = self._manager.get_config_option(
            'manila_service_keypair_name')
        fake_keypair = fake_compute.FakeKeypair(name=keypair_name)
        self.mock_object(self._manager.compute_api, 'keypair_list',
                         mock.Mock(return_value=[]))
        self.mock_object(self._manager.compute_api, 'keypair_import',
                         mock.Mock(return_value=fake_keypair))

        result = self._manager._get_key(self._manager.admin_context)

        self.assertEqual(
            (fake_keypair.name,
             os.path.expanduser(self._manager.get_config_option(
                 'path_to_private_key'))),
            result)
        self._manager.compute_api.keypair_list.assert_called_once_with(
            self._manager.admin_context)
        self._manager.compute_api.keypair_import.assert_called_once_with(
            self._manager.admin_context, keypair_name, '')

    def test_get_key_exists(self):
        fake_keypair = fake_compute.FakeKeypair(
            name=self._manager.get_config_option(
                'manila_service_keypair_name'),
            public_key='fake_public_key')
        self.mock_object(self._manager.compute_api, 'keypair_list',
                         mock.Mock(return_value=[fake_keypair]))
        self.mock_object(self._manager.compute_api, 'keypair_import',
                         mock.Mock(return_value=fake_keypair))
        self.mock_object(self._manager, '_execute',
                         mock.Mock(return_value=('fake_public_key', '')))

        result = self._manager._get_key(self._manager.admin_context)

        self._manager.compute_api.keypair_list.assert_called_once_with(
            self._manager.admin_context)
        self.assertFalse(self._manager.compute_api.keypair_import.called)
        self.assertEqual(
            (fake_keypair.name,
             os.path.expanduser(self._manager.get_config_option(
                 'path_to_private_key'))),
            result)

    def test_get_key_exists_recreate(self):
        fake_keypair = fake_compute.FakeKeypair(
            name=self._manager.get_config_option(
                'manila_service_keypair_name'),
            public_key='fake_public_key1')
        self.mock_object(self._manager.compute_api, 'keypair_list',
                         mock.Mock(return_value=[fake_keypair]))
        self.mock_object(self._manager.compute_api, 'keypair_import',
                         mock.Mock(return_value=fake_keypair))
        self.mock_object(self._manager.compute_api, 'keypair_delete')
        self.mock_object(self._manager, '_execute',
                         mock.Mock(return_value=('fake_public_key2', '')))

        result = self._manager._get_key(self._manager.admin_context)

        self._manager.compute_api.keypair_list.assert_called_once_with(
            self._manager.admin_context)
        self._manager.compute_api.keypair_delete.assert_called_once_with(
            self._manager.admin_context, fake_keypair.id)
        self._manager.compute_api.keypair_import.assert_called_once_with(
            self._manager.admin_context, fake_keypair.name, 'fake_public_key2')
        self.assertEqual(
            (fake_keypair.name,
             os.path.expanduser(self._manager.get_config_option(
                 'path_to_private_key'))),
            result)

    def test_get_key_more_than_one_exist(self):
        fake_keypair = fake_compute.FakeKeypair(
            name=self._manager.get_config_option(
                'manila_service_keypair_name'),
            public_key='fake_public_key1')
        self.mock_object(self._manager.compute_api, 'keypair_list',
                         mock.Mock(return_value=[fake_keypair, fake_keypair]))

        self.assertRaises(
            exception.ServiceInstanceException,
            self._manager._get_key, self._manager.admin_context)
        self._manager.compute_api.keypair_list.assert_called_once_with(
            self._manager.admin_context)

    def test_get_key_keypath_to_public_not_set(self):
        self._manager.path_to_public_key = None
        result = self._manager._get_key(self._manager.admin_context)
        self.assertEqual((None, None), result)

    def test_get_key_keypath_to_private_not_set(self):
        self._manager.path_to_private_key = None
        result = self._manager._get_key(self._manager.admin_context)
        self.assertEqual((None, None), result)

    def test_get_key_incorrect_keypath_to_public(self):
        def exists_side_effect(path):
            return False if path == 'fake_path' else True

        self._manager.path_to_public_key = 'fake_path'
        os_path_exists_mock = mock.Mock(side_effect=exists_side_effect)
        with mock.patch.object(os.path, 'exists', os_path_exists_mock):
            with mock.patch.object(os.path, 'expanduser',
                                   mock.Mock(side_effect=lambda value: value)):
                result = self._manager._get_key(self._manager.admin_context)
                self.assertEqual((None, None), result)

    def test_get_key_incorrect_keypath_to_private(self):
        def exists_side_effect(path):
            return False if path == 'fake_path' else True

        self._manager.path_to_private_key = 'fake_path'
        os_path_exists_mock = mock.Mock(side_effect=exists_side_effect)
        with mock.patch.object(os.path, 'exists', os_path_exists_mock):
            with mock.patch.object(os.path, 'expanduser',
                                   mock.Mock(side_effect=lambda value: value)):
                result = self._manager._get_key(self._manager.admin_context)
                self.assertEqual((None, None), result)

    def test_get_service_image(self):
        fake_image1 = fake_compute.FakeImage(
            name=self._manager.get_config_option('service_image_name'))
        fake_image2 = fake_compute.FakeImage(name='another-image')
        self.mock_object(self._manager.compute_api, 'image_list',
                         mock.Mock(return_value=[fake_image1, fake_image2]))

        result = self._manager._get_service_image(self._manager.admin_context)

        self.assertEqual(fake_image1.id, result)

    def test_get_service_image_not_found(self):
        self.mock_object(self._manager.compute_api, 'image_list',
                         mock.Mock(return_value=[]))
        self.assertRaises(
            exception.ServiceInstanceException,
            self._manager._get_service_image, self._manager.admin_context)

    def test_get_service_image_ambiguous(self):
        fake_image = fake_compute.FakeImage(
            name=fake_get_config_option('service_image_name'))
        fake_images = [fake_image, fake_image]
        self.mock_object(self._manager.compute_api, 'image_list',
                         mock.Mock(return_value=fake_images))
        self.assertRaises(
            exception.ServiceInstanceException,
            self._manager._get_service_image, self._manager.admin_context)

    def test__delete_server_not_found(self):
        self.mock_object(self._manager.compute_api, 'server_delete')
        self.mock_object(
            self._manager.compute_api, 'server_get',
            mock.Mock(side_effect=exception.InstanceNotFound(
                instance_id=self.instance_id)))

        self._manager._delete_server(
            self._manager.admin_context, self.instance_id)

        self.assertFalse(self._manager.compute_api.server_delete.called)
        self._manager.compute_api.server_get.assert_called_once_with(
            self._manager.admin_context, self.instance_id)

    def test__delete_server(self):
        def fake_server_get(*args, **kwargs):
            ctx = args[0]
            if not hasattr(ctx, 'called'):
                ctx.called = True
                return
            else:
                raise exception.InstanceNotFound(instance_id=self.instance_id)

        self.mock_object(self._manager.compute_api, 'server_delete')
        self.mock_object(self._manager.compute_api, 'server_get',
                         mock.Mock(side_effect=fake_server_get))

        self._manager._delete_server(
            self._manager.admin_context, self.instance_id)

        self._manager.compute_api.server_delete.assert_called_once_with(
            self._manager.admin_context, self.instance_id)
        self._manager.compute_api.server_get.assert_has_calls([
            mock.call(self._manager.admin_context, self.instance_id),
            mock.call(self._manager.admin_context, self.instance_id)])

    def test__delete_server_found_always(self):
        self.fake_time = 0

        def fake_time():
            return self.fake_time

        def fake_sleep(time):
            self.fake_time += 1

        self.mock_object(self._manager.compute_api, 'server_delete')
        self.mock_object(self._manager.compute_api, 'server_get')
        self.mock_object(service_instance, 'time')
        self.mock_object(
            service_instance.time, 'time', mock.Mock(side_effect=fake_time))
        self.mock_object(
            service_instance.time, 'sleep', mock.Mock(side_effect=fake_sleep))
        self.mock_object(self._manager, 'max_time_to_build_instance', 2)

        self.assertRaises(
            exception.ServiceInstanceException, self._manager._delete_server,
            self._manager.admin_context, self.instance_id)

        self._manager.compute_api.server_delete.assert_called_once_with(
            self._manager.admin_context, self.instance_id)
        service_instance.time.sleep.assert_has_calls(
            [mock.call(mock.ANY) for i in range(2)])
        service_instance.time.time.assert_has_calls(
            [mock.call() for i in range(4)])
        self._manager.compute_api.server_get.assert_has_calls(
            [mock.call(self._manager.admin_context,
                       self.instance_id) for i in range(3)])

    def test_delete_service_instance(self):
        fake_server_details = dict(
            router_id='foo', subnet_id='bar', instance_id='quuz')
        self.mock_object(self._manager, '_delete_server')
        self.mock_object(self._manager.network_helper, 'teardown_network')

        self._manager.delete_service_instance(
            self._manager.admin_context, fake_server_details)

        self._manager._delete_server.assert_called_once_with(
            self._manager.admin_context, fake_server_details['instance_id'])
        self._manager.network_helper.teardown_network.assert_called_once_with(
            fake_server_details)

    @ddt.data(
        *[{'s': s, 't': t, 'server': server}
            for s, t in (
                ('fake_net_s', 'fake_net_t'),
                ('fake_net_s', '12.34.56.78'),
                ('98.76.54.123', 'fake_net_t'),
                ('98.76.54.123', '12.34.56.78'))
            for server in (
                {'networks': {
                    'fake_net_s': ['foo', '98.76.54.123', 'bar'],
                    'fake_net_t': ['baar', '12.34.56.78', 'quuz']}},
                {'addresses': {
                    'fake_net_s': [
                        {'addr': 'fake1'},
                        {'addr': '98.76.54.123'},
                        {'addr': 'fake2'}],
                    'fake_net_t': [
                        {'addr': 'fake3'},
                        {'addr': '12.34.56.78'},
                        {'addr': 'fake4'}],
                }})])
    @ddt.unpack
    def test_get_common_server_valid_cases(self, s, t, server):
        self._get_common_server(s, t, server, True)

    @ddt.data(
        *[{'s': s, 't': t, 'server': server}
            for s, t in (
                ('fake_net_s', 'fake'),
                ('fake', 'fake_net_t'),
                ('fake', 'fake'),
                ('98.76.54.123', '12.12.12.1212'),
                ('12.12.12.1212', '12.34.56.78'),
                ('12.12.12.1212', '12.12.12.1212'))
            for server in (
                {'networks': {
                    'fake_net_s': ['foo', '98.76.54.123', 'bar'],
                    'fake_net_t': ['baar', '12.34.56.78', 'quuz']}},
                {'addresses': {
                    'fake_net_s': [
                        {'addr': 'fake1'},
                        {'addr': '98.76.54.123'},
                        {'addr': 'fake2'}],
                    'fake_net_t': [
                        {'addr': 'fake3'},
                        {'addr': '12.34.56.78'},
                        {'addr': 'fake4'}],
                }})])
    @ddt.unpack
    def test_get_common_server_invalid_cases(self, s, t, server):
        self._get_common_server(s, t, server, False)

    def _get_common_server(self, s, t, server, is_valid=True):
        fake_instance_id = 'fake_instance_id'
        fake_user = 'fake_user'
        fake_pass = 'fake_pass'
        fake_addr_s = '98.76.54.123'
        fake_addr_t = '12.34.56.78'
        fake_server = {'id': fake_instance_id}
        fake_server.update(server)
        expected = {
            'backend_details': {
                'username': fake_user,
                'password': fake_pass,
                'pk_path': self._manager.path_to_private_key,
                'ip': fake_addr_s,
                'public_address': fake_addr_t,
                'instance_id': fake_instance_id,
            }
        }

        def fake_get_config_option(attr):
            if attr == 'service_net_name_or_ip':
                return s
            elif attr == 'tenant_net_name_or_ip':
                return t
            elif attr == 'service_instance_name_or_id':
                return fake_instance_id
            elif attr == 'service_instance_user':
                return fake_user
            elif attr == 'service_instance_password':
                return fake_pass
            else:
                raise exception.ManilaException("Wrong test data provided.")

        self.mock_object(
            self._manager.compute_api, 'server_get_by_name_or_id',
            mock.Mock(return_value=fake_server))
        self.mock_object(
            self._manager, 'get_config_option',
            mock.Mock(side_effect=fake_get_config_option))

        if is_valid:
            actual = self._manager.get_common_server()
            self.assertEqual(expected, actual)
        else:
            self.assertRaises(
                exception.ManilaException,
                self._manager.get_common_server)
        self.assertTrue(
            self._manager.compute_api.server_get_by_name_or_id.called)

    @ddt.data(service_instance.NOVA_NAME, service_instance.NEUTRON_NAME)
    def test___create_service_instance_with_sg_success(self, helper_type):
        self.mock_object(service_instance, 'NeutronNetworkHelper',
                         mock.Mock(side_effect=FakeNetworkHelper))
        self.mock_object(service_instance, 'NovaNetworkHelper',
                         mock.Mock(side_effect=FakeNetworkHelper))
        config_data = dict(DEFAULT=dict(
            driver_handles_share_servers=True,
            service_instance_user='fake_user',
            service_instance_network_helper_type=helper_type))
        with test_utils.create_temp_config_with_opts(config_data):
            self._manager = service_instance.ServiceInstanceManager()

        server_create = dict(id='fakeid', status='CREATING', networks=dict())
        net_name = self._manager.get_config_option("service_network_name")
        sg = type('FakeSG', (object, ), dict(id='fakeid', name='fakename'))
        ip_address = 'fake_ip_address'
        service_image_id = 'fake_service_image_id'
        key_data = 'fake_key_name', 'fake_key_path'
        instance_name = 'fake_instance_name'
        network_info = dict()
        network_data = dict(nics=['fake_nic1', 'fake_nic2'],
                            service_ip='fake_ip')
        if helper_type == service_instance.NEUTRON_NAME:
            network_data['router'] = dict(id='fake_router_id')
        server_get = dict(
            id='fakeid', status='ACTIVE', networks={net_name: [ip_address]})
        if helper_type == service_instance.NEUTRON_NAME:
            network_data.update(dict(
                router_id='fake_router_id', subnet_id='fake_subnet_id',
                public_port=dict(id='fake_public_port',
                                 fixed_ips=[dict(ip_address=ip_address)]),
                service_port=dict(id='fake_service_port',
                                  fixed_ips=[dict(ip_address=ip_address)])))
        self.mock_object(service_instance.time, 'time',
                         mock.Mock(return_value=5))
        self.mock_object(self._manager.network_helper, 'setup_network',
                         mock.Mock(return_value=network_data))
        self.mock_object(self._manager.network_helper, 'get_network_name',
                         mock.Mock(return_value=net_name))
        self.mock_object(self._manager, '_get_service_image',
                         mock.Mock(return_value=service_image_id))
        self.mock_object(self._manager, '_get_key',
                         mock.Mock(return_value=key_data))
        self.mock_object(self._manager, '_get_or_create_security_group',
                         mock.Mock(return_value=sg))
        self.mock_object(self._manager.compute_api, 'server_create',
                         mock.Mock(return_value=server_create))
        self.mock_object(self._manager.compute_api, 'server_get',
                         mock.Mock(return_value=server_get))
        self.mock_object(self._manager.compute_api,
                         'add_security_group_to_server')
        expected = dict(
            id=server_get['id'],
            status=server_get['status'],
            pk_path=key_data[1],
            public_address=ip_address,
            router_id=network_data.get('router_id'),
            subnet_id=network_data.get('subnet_id'),
            instance_id=server_get['id'],
            ip=ip_address,
            networks=server_get['networks'],
            service_ip='fake_ip')
        if helper_type == service_instance.NEUTRON_NAME:
            expected['router_id'] = network_data['router']['id']
            expected['public_port_id'] = 'fake_public_port'
            expected['service_port_id'] = 'fake_service_port'

        result = self._manager._create_service_instance(
            self._manager.admin_context, instance_name, network_info)

        self.assertEqual(expected, result)
        self.assertTrue(service_instance.time.time.called)
        self._manager.network_helper.setup_network.assert_called_once_with(
            network_info)
        self._manager._get_service_image.assert_called_once_with(
            self._manager.admin_context)
        self._manager._get_key.assert_called_once_with(
            self._manager.admin_context)
        self._manager._get_or_create_security_group.assert_called_once_with(
            self._manager.admin_context)
        self._manager.compute_api.server_create.assert_called_once_with(
            self._manager.admin_context, name=instance_name,
            image=service_image_id, flavor=100,
            key_name=key_data[0], nics=network_data['nics'],
            availability_zone=service_instance.CONF.storage_availability_zone)
        self._manager.compute_api.server_get.assert_called_once_with(
            self._manager.admin_context, server_create['id'])
        if helper_type == service_instance.NEUTRON_NAME:
            self._manager.compute_api.add_security_group_to_server.\
                assert_called_once_with(
                    self._manager.admin_context, server_get['id'], sg.id)
            self._manager.network_helper.get_network_name.assert_has_calls([])
        else:
            self._manager.compute_api.add_security_group_to_server.\
                assert_called_once_with(
                    self._manager.admin_context, server_get['id'], sg.name)
            self._manager.network_helper.get_network_name.\
                assert_called_once_with(network_info)

    @ddt.data(
        dict(
            instance_id_included=False,
            mockobj=mock.Mock(side_effect=exception.ServiceInstanceException)),
        dict(
            instance_id_included=True,
            mockobj=mock.Mock(return_value=dict(id='fakeid', status='ERROR'))))
    @ddt.unpack
    def test___create_service_instance_failed_to_create(
            self, instance_id_included, mockobj):
        service_image_id = 'fake_service_image_id'
        key_data = 'fake_key_name', 'fake_key_path'
        instance_name = 'fake_instance_name'
        network_info = dict()
        network_data = dict(
            nics=['fake_nic1', 'fake_nic2'],
            router_id='fake_router_id', subnet_id='fake_subnet_id')
        self.mock_object(self._manager.network_helper, 'setup_network',
                         mock.Mock(return_value=network_data))
        self.mock_object(self._manager, '_get_service_image',
                         mock.Mock(return_value=service_image_id))
        self.mock_object(self._manager, '_get_key',
                         mock.Mock(return_value=key_data))
        self.mock_object(
            self._manager.compute_api, 'server_create', mockobj)
        self.mock_object(
            self._manager, 'wait_for_instance_to_be_active',
            mock.Mock(side_effect=exception.ServiceInstanceException))

        try:
            self._manager._create_service_instance(
                self._manager.admin_context, instance_name, network_info)
        except exception.ServiceInstanceException as e:
            expected = dict(server_details=dict(
                subnet_id=network_data['subnet_id'],
                router_id=network_data['router_id']))
            if instance_id_included:
                expected['server_details']['instance_id'] = 'fakeid'
            self.assertEqual(expected, e.detail_data)
        else:
            raise exception.ManilaException('Expected error was not raised.')

        self._manager.network_helper.setup_network.assert_called_once_with(
            network_info)
        self._manager._get_service_image.assert_called_once_with(
            self._manager.admin_context)
        self._manager._get_key.assert_called_once_with(
            self._manager.admin_context)
        self._manager.compute_api.server_create.assert_called_once_with(
            self._manager.admin_context, name=instance_name,
            image=service_image_id, flavor=100,
            key_name=key_data[0], nics=network_data['nics'],
            availability_zone=service_instance.CONF.storage_availability_zone)

    def test___create_service_instance_failed_to_build(self):
        server_create = dict(id='fakeid', status='CREATING', networks=dict())
        service_image_id = 'fake_service_image_id'
        key_data = 'fake_key_name', 'fake_key_path'
        instance_name = 'fake_instance_name'
        network_info = dict()
        network_data = dict(
            nics=['fake_nic1', 'fake_nic2'],
            router_id='fake_router_id', subnet_id='fake_subnet_id')
        self.mock_object(self._manager.network_helper, 'setup_network',
                         mock.Mock(return_value=network_data))
        self.mock_object(self._manager, '_get_service_image',
                         mock.Mock(return_value=service_image_id))
        self.mock_object(self._manager, '_get_key',
                         mock.Mock(return_value=key_data))
        self.mock_object(self._manager.compute_api, 'server_create',
                         mock.Mock(return_value=server_create))
        self.mock_object(
            self._manager, 'wait_for_instance_to_be_active',
            mock.Mock(side_effect=exception.ServiceInstanceException))

        try:
            self._manager._create_service_instance(
                self._manager.admin_context, instance_name, network_info)
        except exception.ServiceInstanceException as e:
            self.assertEqual(
                dict(server_details=dict(subnet_id=network_data['subnet_id'],
                                         router_id=network_data['router_id'],
                                         instance_id=server_create['id'])),
                e.detail_data)
        else:
            raise exception.ManilaException('Expected error was not raised.')

        self._manager.network_helper.setup_network.assert_called_once_with(
            network_info)
        self._manager._get_service_image.assert_called_once_with(
            self._manager.admin_context)
        self._manager._get_key.assert_called_once_with(
            self._manager.admin_context)
        self._manager.compute_api.server_create.assert_called_once_with(
            self._manager.admin_context, name=instance_name,
            image=service_image_id, flavor=100,
            key_name=key_data[0], nics=network_data['nics'],
            availability_zone=service_instance.CONF.storage_availability_zone)

    @ddt.data(
        dict(name=None, path=None),
        dict(name=None, path='/tmp'))
    @ddt.unpack
    def test__create_service_instance_no_key_and_no_path(self, name, path):
        key_data = name, path
        self.mock_object(self._manager, '_get_service_image')
        self.mock_object(self._manager, '_get_key',
                         mock.Mock(return_value=key_data))

        self.assertRaises(
            exception.ServiceInstanceException,
            self._manager._create_service_instance,
            self._manager.admin_context, 'fake_instance_name', dict())

        self._manager._get_service_image.assert_called_once_with(
            self._manager.admin_context)
        self._manager._get_key.assert_called_once_with(
            self._manager.admin_context)

    @mock.patch('time.sleep')
    @mock.patch('time.time')
    def _test_wait_for_instance(self, mock_time, mock_sleep,
                                server_get_side_eff=None,
                                expected_try_count=1,
                                expected_sleep_count=0,
                                expected_ret_val=None,
                                expected_exc=None):
        mock_server_get = mock.Mock(side_effect=server_get_side_eff)
        self.mock_object(self._manager.compute_api, 'server_get',
                         mock_server_get)

        self.fake_time = 0

        def fake_time():
            return self.fake_time

        def fake_sleep(sleep_time):
            self.fake_time += sleep_time

        # Note(lpetrut): LOG methods can call time.time
        mock_time.side_effect = fake_time
        mock_sleep.side_effect = fake_sleep
        timeout = 3

        if expected_exc:
            self.assertRaises(
                expected_exc,
                self._manager.wait_for_instance_to_be_active,
                instance_id=mock.sentinel.instance_id,
                timeout=timeout)
        else:
            instance = self._manager.wait_for_instance_to_be_active(
                instance_id=mock.sentinel.instance_id,
                timeout=timeout)
            self.assertEqual(expected_ret_val, instance)

        mock_server_get.assert_has_calls(
            [mock.call(self._manager.admin_context,
                       mock.sentinel.instance_id)] * expected_try_count)
        mock_sleep.assert_has_calls([mock.call(1)] * expected_sleep_count)

    def test_wait_for_instance_timeout(self):
        server_get_side_eff = [
            exception.InstanceNotFound(
                instance_id=mock.sentinel.instance_id),
            {'status': 'BUILDING'},
            {'status': 'ACTIVE'}]
        # Note that in this case, although the status is active, the
        # 'networks' field is missing.
        self._test_wait_for_instance(
            server_get_side_eff=server_get_side_eff,
            expected_exc=exception.ServiceInstanceException,
            expected_try_count=3,
            expected_sleep_count=3)

    def test_wait_for_instance_error_state(self):
        mock_instance = {'status': 'ERROR'}
        self._test_wait_for_instance(
            server_get_side_eff=[mock_instance],
            expected_exc=exception.ServiceInstanceException,
            expected_try_count=1)

    def test_wait_for_instance_available(self):
        mock_instance = {'status': 'ACTIVE',
                         'networks': mock.sentinel.networks}
        self._test_wait_for_instance(
            server_get_side_eff=[mock_instance],
            expected_try_count=1,
            expected_ret_val=mock_instance)

    def test_reboot_server(self):
        fake_server = {'instance_id': mock.sentinel.instance_id}
        soft_reboot = True

        mock_reboot = mock.Mock()
        self.mock_object(self._manager.compute_api, 'server_reboot',
                         mock_reboot)

        self._manager.reboot_server(fake_server, soft_reboot)

        mock_reboot.assert_called_once_with(self._manager.admin_context,
                                            fake_server['instance_id'],
                                            soft_reboot)


class BaseNetworkHelperTestCase(test.TestCase):
    """Tests Base network helper for service instance."""

    def test_instantiate_valid(self):
        class FakeNetworkHelper(service_instance.BaseNetworkhelper):
            @property
            def NAME(self):
                return 'fake_NAME'

            def __init__(self, service_instance_manager):
                self.fake_init = 'fake_init_value'

            def get_network_name(self, network_info):
                return 'fake_network_name'

            def setup_connectivity_with_service_instances(self):
                return 'fake_setup_connectivity_with_service_instances'

            def setup_network(self, network_info):
                return 'fake_setup_network'

            def teardown_network(self, server_details):
                return 'fake_teardown_network'

        instance = FakeNetworkHelper('fake')

        attrs = [
            'fake_init', 'NAME', 'get_network_name', 'teardown_network',
            'setup_connectivity_with_service_instances', 'setup_network',
        ]
        for attr in attrs:
            self.assertTrue(hasattr(instance, attr))
        self.assertEqual('fake_init_value', instance.fake_init)
        self.assertEqual('fake_NAME', instance.NAME)
        self.assertEqual(
            'fake_network_name', instance.get_network_name('fake'))
        self.assertEqual(
            'fake_setup_connectivity_with_service_instances',
            instance.setup_connectivity_with_service_instances())
        self.assertEqual('fake_setup_network', instance.setup_network('fake'))
        self.assertEqual(
            'fake_teardown_network', instance.teardown_network('fake'))

    def test_instantiate_invalid(self):
        self.assertRaises(
            TypeError, service_instance.BaseNetworkhelper, 'fake')


@ddt.ddt
class NeutronNetworkHelperTestCase(test.TestCase):
    """Tests Neutron network helper for service instance."""

    def setUp(self):
        super(NeutronNetworkHelperTestCase, self).setUp()
        self.mock_object(importutils, 'import_class')
        self.fake_manager = FakeServiceInstance()

    def _init_neutron_network_plugin(self):
        self.mock_object(
            service_instance.NeutronNetworkHelper, '_get_service_network_id',
            mock.Mock(return_value='fake_service_network_id'))
        return service_instance.NeutronNetworkHelper(self.fake_manager)

    def test_init_neutron_network_plugin(self):
        instance = self._init_neutron_network_plugin()
        self.assertEqual(service_instance.NEUTRON_NAME, instance.NAME)
        attrs = [
            'neutron_api', 'vif_driver', 'service_network_id',
            'connect_share_server_to_tenant_network', 'get_config_option']
        for attr in attrs:
            self.assertTrue(hasattr(instance, attr), "No attr '%s'" % attr)
        service_instance.NeutronNetworkHelper._get_service_network_id.\
            assert_called_once_with()
        self.assertEqual('DEFAULT', instance.neutron_api.config_group_name)

    def test_init_neutron_network_plugin_with_driver_config_group(self):
        self.fake_manager.driver_config = mock.Mock()
        self.fake_manager.driver_config.config_group =\
            'fake_config_group'
        self.fake_manager.driver_config.network_config_group = None
        instance = self._init_neutron_network_plugin()
        self.assertEqual('fake_config_group',
                         instance.neutron_api.config_group_name)

    def test_init_neutron_network_plugin_with_network_config_group(self):
        self.fake_manager.driver_config = mock.Mock()
        self.fake_manager.driver_config.config_group =\
            "fake_config_group"
        self.fake_manager.driver_config.network_config_group =\
            "fake_network_config_group"
        instance = self._init_neutron_network_plugin()
        self.assertEqual('fake_network_config_group',
                         instance.neutron_api.config_group_name)

    def test_admin_project_id(self):
        instance = self._init_neutron_network_plugin()
        admin_project_id = 'fake_admin_project_id'
        self.mock_class('manila.network.neutron.api.API', mock.Mock())
        instance.neutron_api.admin_project_id = admin_project_id
        self.assertEqual(admin_project_id, instance.admin_project_id)

    def test_get_network_name(self):
        network_info = dict(neutron_net_id='fake_neutron_net_id')
        network = dict(name='fake_network_name')
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            instance.neutron_api, 'get_network',
            mock.Mock(return_value=network))

        result = instance.get_network_name(network_info)

        self.assertEqual(network['name'], result)
        instance.neutron_api.get_network.assert_called_once_with(
            network_info['neutron_net_id'])

    def test_get_service_network_id_none_exist(self):
        service_network_name = fake_get_config_option('service_network_name')
        network = dict(id='fake_network_id')
        admin_project_id = 'fake_admin_project_id'
        self.mock_object(
            service_instance.neutron.API, 'get_all_admin_project_networks',
            mock.Mock(return_value=[]))
        self.mock_object(
            service_instance.neutron.API, 'admin_project_id',
            mock.Mock(return_value=admin_project_id))
        self.mock_object(
            service_instance.neutron.API, 'network_create',
            mock.Mock(return_value=network))
        instance = service_instance.NeutronNetworkHelper(self.fake_manager)

        result = instance._get_service_network_id()

        self.assertEqual(network['id'], result)
        self.assertTrue(service_instance.neutron.API.
                        get_all_admin_project_networks.called)
        service_instance.neutron.API.network_create.assert_has_calls([
            mock.call(instance.admin_project_id, service_network_name)])

    def test_get_service_network_id_one_exist(self):
        service_network_name = fake_get_config_option('service_network_name')
        network = dict(id='fake_network_id', name=service_network_name)
        admin_project_id = 'fake_admin_project_id'
        self.mock_object(
            service_instance.neutron.API, 'get_all_admin_project_networks',
            mock.Mock(return_value=[network]))
        self.mock_object(
            service_instance.neutron.API, 'admin_project_id',
            mock.Mock(return_value=admin_project_id))
        instance = service_instance.NeutronNetworkHelper(self.fake_manager)

        result = instance._get_service_network_id()

        self.assertEqual(network['id'], result)
        self.assertTrue(service_instance.neutron.API.
                        get_all_admin_project_networks.called)

    def test_get_service_network_id_two_exist(self):
        service_network_name = fake_get_config_option('service_network_name')
        network = dict(id='fake_network_id', name=service_network_name)
        self.mock_object(
            service_instance.neutron.API, 'get_all_admin_project_networks',
            mock.Mock(return_value=[network, network]))

        helper = service_instance.NeutronNetworkHelper(self.fake_manager)
        self.assertRaises(exception.ManilaException,
                          lambda: helper.service_network_id)

        service_instance.neutron.API.get_all_admin_project_networks.\
            assert_has_calls([mock.call()])

    @ddt.data(dict(), dict(subnet_id='foo'), dict(router_id='bar'))
    def test_teardown_network_no_service_data(self, server_details):
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            service_instance.neutron.API, 'router_remove_interface')

        instance.teardown_network(server_details)

        self.assertFalse(
            service_instance.neutron.API.router_remove_interface.called)

    @ddt.data(
        *[dict(server_details=sd, fail=f) for f in (True, False)
            for sd in (dict(service_port_id='fake_service_port_id'),
                       dict(public_port_id='fake_public_port_id'),
                       dict(service_port_id='fake_service_port_id',
                            public_port_id='fake_public_port_id'))]
    )
    @ddt.unpack
    def test_teardown_network_with_ports(self, server_details, fail):
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            service_instance.neutron.API, 'router_remove_interface')
        if fail:
            delete_port_mock = mock.Mock(
                side_effect=exception.NetworkException(code=404))
        else:
            delete_port_mock = mock.Mock()
        self.mock_object(instance.neutron_api, 'delete_port', delete_port_mock)
        self.mock_object(service_instance.LOG, 'debug')

        instance.teardown_network(server_details)

        self.assertFalse(instance.neutron_api.router_remove_interface.called)
        self.assertEqual(
            len(server_details),
            len(instance.neutron_api.delete_port.mock_calls))
        for k, v in server_details.items():
            self.assertIn(
                mock.call(v), instance.neutron_api.delete_port.mock_calls)
        if fail:
            service_instance.LOG.debug.assert_has_calls([
                mock.call(mock.ANY, mock.ANY) for sd in server_details
            ])
        else:
            service_instance.LOG.debug.assert_has_calls([])

    @ddt.data(
        dict(service_port_id='fake_service_port_id'),
        dict(public_port_id='fake_public_port_id'),
        dict(service_port_id='fake_service_port_id',
             public_port_id='fake_public_port_id'),
    )
    def test_teardown_network_with_ports_unhandled_exception(self,
                                                             server_details):
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            service_instance.neutron.API, 'router_remove_interface')
        delete_port_mock = mock.Mock(
            side_effect=exception.NetworkException(code=500))
        self.mock_object(
            service_instance.neutron.API, 'delete_port', delete_port_mock)
        self.mock_object(service_instance.LOG, 'debug')

        self.assertRaises(
            exception.NetworkException,
            instance.teardown_network,
            server_details,
        )

        self.assertFalse(
            service_instance.neutron.API.router_remove_interface.called)
        service_instance.neutron.API.delete_port.assert_called_once_with(
            mock.ANY)
        service_instance.LOG.debug.assert_has_calls([])

    def test_teardown_network_with_wrong_ports(self):
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            service_instance.neutron.API, 'router_remove_interface')
        self.mock_object(
            service_instance.neutron.API, 'delete_port')
        self.mock_object(service_instance.LOG, 'debug')

        instance.teardown_network(dict(foo_id='fake_service_port_id'))

        service_instance.neutron.API.router_remove_interface.assert_has_calls(
            [])
        service_instance.neutron.API.delete_port.assert_has_calls([])
        service_instance.LOG.debug.assert_has_calls([])

    def test_teardown_network_subnet_is_used(self):
        server_details = dict(subnet_id='foo', router_id='bar')
        fake_ports = [
            {'fixed_ips': [{'subnet_id': server_details['subnet_id']}],
             'device_id': 'fake_device_id',
             'device_owner': 'compute:foo'},
        ]
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            service_instance.neutron.API, 'router_remove_interface')
        self.mock_object(
            service_instance.neutron.API, 'update_subnet')
        self.mock_object(
            service_instance.neutron.API, 'list_ports',
            mock.Mock(return_value=fake_ports))

        instance.teardown_network(server_details)

        self.assertFalse(
            service_instance.neutron.API.router_remove_interface.called)
        self.assertFalse(service_instance.neutron.API.update_subnet.called)
        service_instance.neutron.API.list_ports.assert_called_once_with(
            fields=['fixed_ips', 'device_id', 'device_owner'])

    def test_teardown_network_subnet_not_used(self):
        server_details = dict(subnet_id='foo', router_id='bar')
        fake_ports = [
            {'fixed_ips': [{'subnet_id': server_details['subnet_id']}],
             'device_id': 'fake_device_id',
             'device_owner': 'network:router_interface'},
            {'fixed_ips': [{'subnet_id': 'bar' + server_details['subnet_id']}],
             'device_id': 'fake_device_id',
             'device_owner': 'compute'},
            {'fixed_ips': [{'subnet_id': server_details['subnet_id']}],
             'device_id': '',
             'device_owner': 'compute'},
        ]
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            service_instance.neutron.API, 'router_remove_interface')
        self.mock_object(
            service_instance.neutron.API, 'update_subnet')
        self.mock_object(
            service_instance.neutron.API, 'list_ports',
            mock.Mock(return_value=fake_ports))

        instance.teardown_network(server_details)

        service_instance.neutron.API.router_remove_interface.\
            assert_called_once_with('bar', 'foo')
        service_instance.neutron.API.update_subnet.\
            assert_called_once_with('foo', '')
        service_instance.neutron.API.list_ports.assert_called_once_with(
            fields=['fixed_ips', 'device_id', 'device_owner'])

    def test_teardown_network_subnet_not_used_and_get_error_404(self):
        server_details = dict(subnet_id='foo', router_id='bar')
        fake_ports = [
            {'fixed_ips': [{'subnet_id': server_details['subnet_id']}],
             'device_id': 'fake_device_id',
             'device_owner': 'fake'},
        ]
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            service_instance.neutron.API, 'router_remove_interface',
            mock.Mock(side_effect=exception.NetworkException(code=404)))
        self.mock_object(
            service_instance.neutron.API, 'update_subnet')
        self.mock_object(
            service_instance.neutron.API, 'list_ports',
            mock.Mock(return_value=fake_ports))

        instance.teardown_network(server_details)

        service_instance.neutron.API.router_remove_interface.\
            assert_called_once_with('bar', 'foo')
        service_instance.neutron.API.update_subnet.\
            assert_called_once_with('foo', '')
        service_instance.neutron.API.list_ports.assert_called_once_with(
            fields=['fixed_ips', 'device_id', 'device_owner'])

    def test_teardown_network_subnet_not_used_get_unhandled_error(self):
        server_details = dict(subnet_id='foo', router_id='bar')
        fake_ports = [
            {'fixed_ips': [{'subnet_id': server_details['subnet_id']}],
             'device_id': 'fake_device_id',
             'device_owner': 'fake'},
        ]
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            service_instance.neutron.API, 'router_remove_interface',
            mock.Mock(side_effect=exception.NetworkException(code=500)))
        self.mock_object(
            service_instance.neutron.API, 'update_subnet')
        self.mock_object(
            service_instance.neutron.API, 'list_ports',
            mock.Mock(return_value=fake_ports))

        self.assertRaises(
            exception.NetworkException,
            instance.teardown_network, server_details)

        service_instance.neutron.API.router_remove_interface.\
            assert_called_once_with('bar', 'foo')
        self.assertFalse(service_instance.neutron.API.update_subnet.called)
        service_instance.neutron.API.list_ports.assert_called_once_with(
            fields=['fixed_ips', 'device_id', 'device_owner'])

    def test_setup_network_and_connect_share_server_to_tenant_net(self):
        def fake_create_port(*aargs, **kwargs):
            if aargs[1] == 'fake_service_network_id':
                return self.service_port
            elif aargs[1] == 'fake_tenant_network_id':
                return self.public_port
            else:
                raise exception.ManilaException('Got unexpected data')

        admin_project_id = 'fake_admin_project_id'
        network_info = dict(
            neutron_net_id='fake_tenant_network_id',
            neutron_subnet_id='fake_tenant_subnet_id')
        cidr = '13.0.0.0/24'
        self.service_port = dict(
            id='fake_service_port_id',
            fixed_ips=[dict(ip_address='fake_service_port_ip_address')])
        self.public_port = dict(
            id='fake_tenant_port_id',
            fixed_ips=[dict(ip_address='fake_public_port_ip_address')])
        service_subnet = dict(id='fake_service_subnet')
        instance = self._init_neutron_network_plugin()
        instance.connect_share_server_to_tenant_network = True
        self.mock_object(instance, '_get_service_network_id',
                         mock.Mock(return_value='fake_service_network_id'))
        self.mock_object(
            service_instance.neutron.API, 'admin_project_id',
            mock.Mock(return_value=admin_project_id))
        self.mock_object(
            service_instance.neutron.API, 'create_port',
            mock.Mock(side_effect=fake_create_port))
        self.mock_object(
            service_instance.neutron.API, 'subnet_create',
            mock.Mock(return_value=service_subnet))
        self.mock_object(
            instance, 'setup_connectivity_with_service_instances',
            mock.Mock(return_value=service_subnet))
        self.mock_object(
            instance, '_get_cidr_for_subnet', mock.Mock(return_value=cidr))
        self.mock_object(
            instance, '_get_service_subnet', mock.Mock(return_value=None))
        self.mock_object(
            instance, '_get_service_ip', mock.Mock(return_value='fake_ip'))
        expected = dict(
            ip_address=self.public_port['fixed_ips'][0]['ip_address'],
            public_port=self.public_port, service_ip='fake_ip',
            service_port=self.service_port, service_subnet=service_subnet,
            ports=[self.service_port, self.public_port],
            nics=[{'port-id': self.service_port['id']},
                  {'port-id': self.public_port['id']}])

        result = instance.setup_network(network_info)

        self.assertEqual(expected, result)
        instance.setup_connectivity_with_service_instances.\
            assert_called_once_with()
        instance._get_service_subnet.assert_called_once_with(mock.ANY)
        instance._get_cidr_for_subnet.assert_called_once_with()
        self.assertTrue(service_instance.neutron.API.subnet_create.called)
        self.assertTrue(service_instance.neutron.API.create_port.called)
        self.assertTrue(instance._get_service_ip.called)

    @ddt.data(None, exception.NetworkException(code=400))
    def test_setup_network_using_router_success(self, return_obj):
        admin_project_id = 'fake_admin_project_id'
        network_info = dict(
            neutron_net_id='fake_tenant_network_id',
            neutron_subnet_id='fake_tenant_subnet_id')
        cidr = '13.0.0.0/24'
        self.service_port = dict(
            id='fake_service_port_id',
            fixed_ips=[dict(ip_address='fake_service_port_ip_address')])
        service_subnet = dict(id='fake_service_subnet')
        instance = self._init_neutron_network_plugin()
        instance.connect_share_server_to_tenant_network = False
        self.mock_object(instance, '_get_service_network_id',
                         mock.Mock(return_value='fake_service_network_id'))
        router = dict(id='fake_router_id')
        self.mock_object(
            service_instance.neutron.API, 'admin_project_id',
            mock.Mock(return_value=admin_project_id))
        self.mock_object(
            service_instance.neutron.API, 'create_port',
            mock.Mock(return_value=self.service_port))
        self.mock_object(
            service_instance.neutron.API, 'subnet_create',
            mock.Mock(return_value=service_subnet))
        self.mock_object(
            instance, '_get_private_router', mock.Mock(return_value=router))
        self.mock_object(
            service_instance.neutron.API, 'router_add_interface',
            mock.Mock(side_effect=return_obj))
        self.mock_object(instance, 'setup_connectivity_with_service_instances')
        self.mock_object(
            instance, '_get_cidr_for_subnet', mock.Mock(return_value=cidr))
        self.mock_object(
            instance, '_get_service_subnet', mock.Mock(return_value=None))
        self.mock_object(
            instance, '_get_service_ip', mock.Mock(return_value='fake_ip'))
        expected = dict(
            ip_address=self.service_port['fixed_ips'][0]['ip_address'],
            service_port=self.service_port, service_subnet=service_subnet,
            ports=[self.service_port], router=router, service_ip='fake_ip',
            nics=[{'port-id': self.service_port['id']}])

        result = instance.setup_network(network_info)

        self.assertEqual(expected, result)
        instance.setup_connectivity_with_service_instances.\
            assert_called_once_with()
        instance._get_service_subnet.assert_called_once_with(mock.ANY)
        instance._get_cidr_for_subnet.assert_called_once_with()
        self.assertTrue(service_instance.neutron.API.subnet_create.called)
        self.assertTrue(service_instance.neutron.API.create_port.called)
        instance._get_private_router.assert_called_once_with(
            network_info['neutron_net_id'], network_info['neutron_subnet_id'])
        service_instance.neutron.API.router_add_interface.\
            assert_called_once_with(router['id'], service_subnet['id'])
        self.assertTrue(instance._get_service_ip.called)

    def test_setup_network_using_router_addon_of_interface_failed(self):
        network_info = dict(
            neutron_net_id='fake_tenant_network_id',
            neutron_subnet_id='fake_tenant_subnet_id')
        service_subnet = dict(id='fake_service_subnet')
        instance = self._init_neutron_network_plugin()
        instance.connect_share_server_to_tenant_network = False
        self.mock_object(instance, '_get_service_network_id',
                         mock.Mock(return_value='fake_service_network_id'))
        router = dict(id='fake_router_id')
        self.mock_object(
            instance, '_get_private_router', mock.Mock(return_value=router))
        self.mock_object(
            service_instance.neutron.API, 'router_add_interface',
            mock.Mock(side_effect=exception.NetworkException(code=500)))
        self.mock_object(
            instance, '_get_service_subnet',
            mock.Mock(return_value=service_subnet))

        self.assertRaises(
            exception.NetworkException,
            instance.setup_network, network_info)

        instance._get_service_subnet.assert_called_once_with(mock.ANY)
        instance._get_private_router.assert_called_once_with(
            network_info['neutron_net_id'], network_info['neutron_subnet_id'])
        service_instance.neutron.API.router_add_interface.\
            assert_called_once_with(router['id'], service_subnet['id'])

    def test_setup_network_using_router_connectivity_verification_fail(self):
        admin_project_id = 'fake_admin_project_id'
        network_info = dict(
            neutron_net_id='fake_tenant_network_id',
            neutron_subnet_id='fake_tenant_subnet_id')
        cidr = '13.0.0.0/24'
        self.service_port = dict(
            id='fake_service_port_id',
            fixed_ips=[dict(ip_address='fake_service_port_ip_address')])
        service_subnet = dict(id='fake_service_subnet')
        instance = self._init_neutron_network_plugin()
        instance.connect_share_server_to_tenant_network = False
        self.mock_object(instance, '_get_service_network_id',
                         mock.Mock(return_value='fake_service_network_id'))
        router = dict(id='fake_router_id')
        self.mock_object(
            service_instance.neutron.API, 'admin_project_id',
            mock.Mock(return_value=admin_project_id))
        self.mock_object(
            service_instance.neutron.API, 'create_port',
            mock.Mock(return_value=self.service_port))
        self.mock_object(
            service_instance.neutron.API, 'subnet_create',
            mock.Mock(return_value=service_subnet))
        self.mock_object(service_instance.neutron.API, 'delete_port')
        self.mock_object(
            instance, '_get_private_router', mock.Mock(return_value=router))
        self.mock_object(
            service_instance.neutron.API, 'router_add_interface')
        self.mock_object(
            instance, 'setup_connectivity_with_service_instances',
            mock.Mock(side_effect=exception.ManilaException('Fake')))
        self.mock_object(
            instance, '_get_cidr_for_subnet', mock.Mock(return_value=cidr))
        self.mock_object(
            instance, '_get_service_subnet', mock.Mock(return_value=None))

        self.assertRaises(
            exception.ManilaException, instance.setup_network, network_info)

        instance.setup_connectivity_with_service_instances.\
            assert_called_once_with()
        instance._get_service_subnet.assert_called_once_with(mock.ANY)
        instance._get_cidr_for_subnet.assert_called_once_with()
        self.assertTrue(service_instance.neutron.API.subnet_create.called)
        self.assertTrue(service_instance.neutron.API.create_port.called)
        instance._get_private_router.assert_called_once_with(
            network_info['neutron_net_id'], network_info['neutron_subnet_id'])
        service_instance.neutron.API.router_add_interface.\
            assert_called_once_with(router['id'], service_subnet['id'])
        service_instance.neutron.API.delete_port.assert_has_calls([
            mock.call(self.service_port['id'])])

    def test__get_service_ip(self):
        fake_division_mask = fake_get_config_option(
            'service_network_division_mask')
        fake_subnet = fake_network.FakeSubnet(
            cidr='10.254.0.0/%s' % fake_division_mask)
        fake_port = fake_network.FakePort(fixed_ips=[
            {'subnet_id': fake_subnet['id'], 'ip_address': '10.254.0.2'}],
            mac_address='fake_mac_address')

        instance = self._init_neutron_network_plugin()
        result = instance._get_service_ip(fake_port, fake_subnet['id'])

        # result should be equal to fake_port.fixed_ips[0]['ip_address']
        self.assertEqual(fake_port.fixed_ips[0]['ip_address'], result)

    def test__get_service_ip_exception(self):

        fake_division_mask = fake_get_config_option(
            'service_network_division_mask')
        fake_subnet = fake_network.FakeSubnet(
            cidr='10.254.0.0/%s' % fake_division_mask)
        fake_port = fake_network.FakePort(fixed_ips=[
            {'subnet_id': 'another_fake_id', 'ip_address': '10.254.0.2'}],
            mac_address='fake_mac_address')

        instance = self._init_neutron_network_plugin()
        self.assertRaises(
            exception.ServiceIPNotFound,
            instance._get_service_ip, fake_port, fake_subnet['id'])

    def test__get_cidr_for_subnet_success(self):
        expected = (
            fake_get_config_option('service_network_cidr').split('/')[0] +
            '/' + six.text_type(
                fake_get_config_option('service_network_division_mask')))
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            instance, '_get_all_service_subnets', mock.Mock(return_value=[]))

        result = instance._get_cidr_for_subnet()

        self.assertEqual(expected, result)
        instance._get_all_service_subnets.assert_called_once_with()

    def test__get_cidr_for_subnet_failure(self):
        subnets = []
        serv_cidr = netaddr.IPNetwork(
            fake_get_config_option('service_network_cidr'))
        division_mask = fake_get_config_option('service_network_division_mask')
        for subnet in serv_cidr.subnet(division_mask):
            subnets.append(dict(cidr=six.text_type(subnet.cidr)))
        instance = self._init_neutron_network_plugin()
        self.mock_object(
            instance, '_get_all_service_subnets',
            mock.Mock(return_value=subnets))

        self.assertRaises(
            exception.ServiceInstanceException,
            instance._get_cidr_for_subnet)

        instance._get_all_service_subnets.assert_called_once_with()

    def test_setup_connectivity_with_service_instances(self):
        instance = self._init_neutron_network_plugin()
        interface_name = 'fake_interface_name'
        fake_division_mask = fake_get_config_option(
            'service_network_division_mask')
        fake_subnet = fake_network.FakeSubnet(
            cidr='10.254.0.0/%s' % fake_division_mask)
        fake_port = fake_network.FakePort(fixed_ips=[
            {'subnet_id': fake_subnet['id'], 'ip_address': '10.254.0.2'}],
            mac_address='fake_mac_address')

        self.mock_object(instance, '_get_service_port',
                         mock.Mock(return_value=fake_port))
        self.mock_object(instance, '_add_fixed_ips_to_service_port',
                         mock.Mock(return_value=fake_port))
        self.mock_object(instance.vif_driver, 'get_device_name',
                         mock.Mock(return_value=interface_name))
        self.mock_object(instance.neutron_api, 'get_subnet',
                         mock.Mock(return_value=fake_subnet))
        self.mock_object(instance, '_remove_outdated_interfaces')
        self.mock_object(instance.vif_driver, 'plug')
        device_mock = mock.Mock()
        self.mock_object(service_instance.ip_lib, 'IPDevice',
                         mock.Mock(return_value=device_mock))

        result = instance.setup_connectivity_with_service_instances()

        instance._get_service_port.assert_called_once_with()
        instance.vif_driver.get_device_name.assert_called_once_with(fake_port)
        instance.vif_driver.plug.assert_called_once_with(
            interface_name, fake_port['id'], fake_port['mac_address'])
        instance.neutron_api.get_subnet.assert_called_once_with(
            fake_subnet['id'])
        instance.vif_driver.init_l3.assert_called_once_with(
            interface_name, ['10.254.0.2/%s' % fake_division_mask])
        service_instance.ip_lib.IPDevice.assert_called_once_with(
            interface_name)
        device_mock.route.pullup_route.assert_called_once_with(interface_name)
        instance._remove_outdated_interfaces.assert_called_once_with(
            device_mock)

        # result should be equal to fake_port
        self.assertEqual(fake_port, result)

    def test__get_set_of_device_cidrs(self):
        device = fake_network.FakeDevice('foo')
        expected = set(('1.0.0.0/27', '2.0.0.0/27'))
        instance = self._init_neutron_network_plugin()

        result = instance._get_set_of_device_cidrs(device)

        self.assertEqual(expected, result)

    def test__remove_outdated_interfaces(self):
        device = fake_network.FakeDevice(
            'foobarquuz', [dict(ip_version=4, cidr='1.0.0.0/27')])
        devices = [fake_network.FakeDevice('foobar')]
        instance = self._init_neutron_network_plugin()
        self.mock_object(instance.vif_driver, 'unplug')
        self.mock_object(
            service_instance.ip_lib.IPWrapper, 'get_devices',
            mock.Mock(return_value=devices))

        instance._remove_outdated_interfaces(device)

        instance.vif_driver.unplug.assert_called_once_with('foobar')

    def test__get_service_port_none_exist(self):
        instance = self._init_neutron_network_plugin()
        admin_project_id = 'fake_admin_project_id'
        fake_port_values = {'device_id': 'manila-share',
                            'binding:host_id': 'fake_host'}
        self.mock_object(
            service_instance.neutron.API, 'admin_project_id',
            mock.Mock(return_value=admin_project_id))
        fake_service_port = fake_network.FakePort(device_id='manila-share')
        self.mock_object(instance.neutron_api, 'list_ports',
                         mock.Mock(return_value=[]))
        self.mock_object(service_instance.socket, 'gethostname',
                         mock.Mock(return_value='fake_host'))
        self.mock_object(instance.neutron_api, 'create_port',
                         mock.Mock(return_value=fake_service_port))
        self.mock_object(instance.neutron_api, 'update_port_fixed_ips',
                         mock.Mock(return_value=fake_service_port))

        result = instance._get_service_port()

        instance.neutron_api.list_ports.assert_called_once_with(
            **fake_port_values)
        instance.neutron_api.create_port.assert_called_once_with(
            instance.admin_project_id, instance.service_network_id,
            device_id='manila-share', device_owner='manila:share',
            host_id='fake_host')
        service_instance.socket.gethostname.assert_called_once_with()
        self.assertFalse(instance.neutron_api.update_port_fixed_ips.called)
        self.assertEqual(fake_service_port, result)

    def test__get_service_port_one_exist_on_same_host(self):
        instance = self._init_neutron_network_plugin()
        fake_port_values = {'device_id': 'manila-share',
                            'binding:host_id': 'fake_host'}
        fake_service_port = fake_network.FakePort(**fake_port_values)
        self.mock_object(service_instance.socket, 'gethostname',
                         mock.Mock(return_value='fake_host'))
        self.mock_object(instance.neutron_api, 'list_ports',
                         mock.Mock(return_value=[fake_service_port]))
        self.mock_object(instance.neutron_api, 'create_port',
                         mock.Mock(return_value=fake_service_port))
        self.mock_object(instance.neutron_api, 'update_port_fixed_ips',
                         mock.Mock(return_value=fake_service_port))

        result = instance._get_service_port()

        instance.neutron_api.list_ports.assert_called_once_with(
            **fake_port_values)
        self.assertFalse(instance.neutron_api.create_port.called)
        self.assertFalse(instance.neutron_api.update_port_fixed_ips.called)
        self.assertEqual(fake_service_port, result)

    def test__get_service_port_one_exist_on_different_host(self):
        instance = self._init_neutron_network_plugin()
        admin_project_id = 'fake_admin_project_id'
        fake_port = {'device_id': 'manila-share',
                     'binding:host_id': 'fake_host'}
        self.mock_object(
            service_instance.neutron.API, 'admin_project_id',
            mock.Mock(return_value=admin_project_id))
        fake_service_port = fake_network.FakePort(**fake_port)
        self.mock_object(instance.neutron_api, 'list_ports',
                         mock.Mock(return_value=[]))
        self.mock_object(service_instance.socket, 'gethostname',
                         mock.Mock(return_value='fake_host'))
        self.mock_object(instance.neutron_api, 'create_port',
                         mock.Mock(return_value=fake_service_port))
        self.mock_object(instance.neutron_api, 'update_port_fixed_ips',
                         mock.Mock(return_value=fake_service_port))

        result = instance._get_service_port()

        instance.neutron_api.list_ports.assert_called_once_with(
            **fake_port)
        instance.neutron_api.create_port.assert_called_once_with(
            instance.admin_project_id, instance.service_network_id,
            device_id='manila-share', device_owner='manila:share',
            host_id='fake_host')
        service_instance.socket.gethostname.assert_called_once_with()
        self.assertFalse(instance.neutron_api.update_port_fixed_ips.called)
        self.assertEqual(fake_service_port, result)

    def test__get_service_port_two_exist_on_same_host(self):
        instance = self._init_neutron_network_plugin()
        fake_service_port = fake_network.FakePort(**{
            'device_id': 'manila-share', 'binding:host_id': 'fake_host'})
        self.mock_object(
            instance.neutron_api, 'list_ports',
            mock.Mock(return_value=[fake_service_port, fake_service_port]))
        self.mock_object(service_instance.socket, 'gethostname',
                         mock.Mock(return_value='fake_host'))
        self.mock_object(instance.neutron_api, 'create_port',
                         mock.Mock(return_value=fake_service_port))
        self.assertRaises(
            exception.ServiceInstanceException, instance._get_service_port)
        self.assertFalse(instance.neutron_api.create_port.called)

    def test__add_fixed_ips_to_service_port(self):
        ip_address1 = '13.0.0.13'
        subnet_id1 = 'fake_subnet_id1'
        subnet_id2 = 'fake_subnet_id2'
        port = dict(id='fooport', fixed_ips=[dict(
            subnet_id=subnet_id1, ip_address=ip_address1)])
        expected = mock.Mock()
        network = dict(subnets=[subnet_id1, subnet_id2])
        instance = self._init_neutron_network_plugin()
        self.mock_object(instance.neutron_api, 'get_network',
                         mock.Mock(return_value=network))
        self.mock_object(instance.neutron_api, 'update_port_fixed_ips',
                         mock.Mock(return_value=expected))

        result = instance._add_fixed_ips_to_service_port(port)

        self.assertEqual(expected, result)
        instance.neutron_api.get_network.assert_called_once_with(
            instance.service_network_id)
        instance.neutron_api.update_port_fixed_ips.assert_called_once_with(
            port['id'], dict(fixed_ips=[
                dict(subnet_id=subnet_id1, ip_address=ip_address1),
                dict(subnet_id=subnet_id2)]))

    def test__get_private_router_success(self):
        instance = self._init_neutron_network_plugin()
        network = fake_network.FakeNetwork()
        subnet = fake_network.FakeSubnet(gateway_ip='fake_ip')
        router = fake_network.FakeRouter(id='fake_router_id')
        port = fake_network.FakePort(fixed_ips=[
            dict(subnet_id=subnet['id'],
                 ip_address=subnet['gateway_ip'])],
            device_id=router['id'])
        self.mock_object(instance.neutron_api, 'get_subnet',
                         mock.Mock(return_value=subnet))
        self.mock_object(instance.neutron_api, 'list_ports',
                         mock.Mock(return_value=[port]))
        self.mock_object(instance.neutron_api, 'show_router',
                         mock.Mock(return_value=router))

        result = instance._get_private_router(network['id'], subnet['id'])

        self.assertEqual(router, result)
        instance.neutron_api.get_subnet.assert_called_once_with(subnet['id'])
        instance.neutron_api.list_ports.assert_called_once_with(
            network_id=network['id'])
        instance.neutron_api.show_router.assert_called_once_with(router['id'])

    def test__get_private_router_no_gateway(self):
        instance = self._init_neutron_network_plugin()
        subnet = fake_network.FakeSubnet(gateway_ip='')
        self.mock_object(instance.neutron_api, 'get_subnet',
                         mock.Mock(return_value=subnet))

        self.assertRaises(
            exception.ServiceInstanceException,
            instance._get_private_router, 'fake_network_id', subnet['id'])

        instance.neutron_api.get_subnet.assert_called_once_with(
            subnet['id'])

    def test__get_private_router_subnet_is_not_attached_to_the_router(self):
        instance = self._init_neutron_network_plugin()
        network_id = 'fake_network_id'
        subnet = fake_network.FakeSubnet(gateway_ip='fake_ip')
        self.mock_object(instance.neutron_api, 'get_subnet',
                         mock.Mock(return_value=subnet))
        self.mock_object(instance.neutron_api, 'list_ports',
                         mock.Mock(return_value=[]))

        self.assertRaises(
            exception.ServiceInstanceException,
            instance._get_private_router, network_id, subnet['id'])

        instance.neutron_api.get_subnet.assert_called_once_with(
            subnet['id'])
        instance.neutron_api.list_ports.assert_called_once_with(
            network_id=network_id)

    def test__get_service_subnet_none_found(self):
        subnet_name = 'fake_subnet_name'
        instance = self._init_neutron_network_plugin()
        self.mock_object(instance, '_get_all_service_subnets',
                         mock.Mock(return_value=[]))

        result = instance._get_service_subnet(subnet_name)

        self.assertIsNone(result)
        instance._get_all_service_subnets.assert_called_once_with()

    def test__get_service_subnet_unused_found(self):
        subnet_name = 'fake_subnet_name'
        subnets = [fake_network.FakeSubnet(id='foo', name=''),
                   fake_network.FakeSubnet(id='bar', name='quuz')]
        instance = self._init_neutron_network_plugin()
        self.mock_object(instance.neutron_api, 'update_subnet')
        self.mock_object(instance, '_get_all_service_subnets',
                         mock.Mock(return_value=subnets))

        result = instance._get_service_subnet(subnet_name)

        self.assertEqual(subnets[0], result)
        instance._get_all_service_subnets.assert_called_once_with()
        instance.neutron_api.update_subnet.assert_called_once_with(
            subnets[0]['id'], subnet_name)

    def test__get_service_subnet_one_found(self):
        subnet_name = 'fake_subnet_name'
        subnets = [fake_network.FakeSubnet(id='foo', name='quuz'),
                   fake_network.FakeSubnet(id='bar', name=subnet_name)]
        instance = self._init_neutron_network_plugin()
        self.mock_object(instance, '_get_all_service_subnets',
                         mock.Mock(return_value=subnets))

        result = instance._get_service_subnet(subnet_name)

        self.assertEqual(subnets[1], result)
        instance._get_all_service_subnets.assert_called_once_with()

    def test__get_service_subnet_two_found(self):
        subnet_name = 'fake_subnet_name'
        subnets = [fake_network.FakeSubnet(id='foo', name=subnet_name),
                   fake_network.FakeSubnet(id='bar', name=subnet_name)]
        instance = self._init_neutron_network_plugin()
        self.mock_object(instance, '_get_all_service_subnets',
                         mock.Mock(return_value=subnets))

        self.assertRaises(
            exception.ServiceInstanceException,
            instance._get_service_subnet, subnet_name)

        instance._get_all_service_subnets.assert_called_once_with()

    def test__get_all_service_subnets(self):
        subnet_id1 = 'fake_subnet_id1'
        subnet_id2 = 'fake_subnet_id2'
        instance = self._init_neutron_network_plugin()
        network = dict(subnets=[subnet_id1, subnet_id2])
        self.mock_object(instance.neutron_api, 'get_subnet',
                         mock.Mock(side_effect=lambda s_id: dict(id=s_id)))
        self.mock_object(instance.neutron_api, 'get_network',
                         mock.Mock(return_value=network))

        result = instance._get_all_service_subnets()

        self.assertEqual([dict(id=subnet_id1), dict(id=subnet_id2)], result)
        instance.neutron_api.get_network.assert_called_once_with(
            instance.service_network_id)
        instance.neutron_api.get_subnet.assert_has_calls([
            mock.call(subnet_id1), mock.call(subnet_id2)])


@ddt.ddt
class NovaNetworkHelperTestCase(test.TestCase):
    """Tests Nova network helper for service instance."""

    def setUp(self):
        super(NovaNetworkHelperTestCase, self).setUp()
        self.fake_manager = FakeServiceInstance()

    def test_init(self):
        instance = service_instance.NovaNetworkHelper(self.fake_manager)
        self.assertEqual(service_instance.NOVA_NAME, instance.NAME)
        self.assertIsNone(instance.teardown_network('fake'))
        self.assertIsNone(
            instance.setup_connectivity_with_service_instances())

    def test_get_network_name(self):
        network_info = dict(nova_net_id='fake_nova_net_id')
        network = dict(label='fake_network')
        instance = service_instance.NovaNetworkHelper(self.fake_manager)
        self.mock_object(instance.compute_api, 'network_get',
                         mock.Mock(return_value=network))

        result = instance.get_network_name(network_info)

        self.assertEqual(network['label'], result)
        instance.compute_api.network_get.assert_called_once_with(
            instance.admin_context, network_info['nova_net_id'])

    @ddt.data(None, [], {}, '')
    def test_get_network_name_invalid(self, net_name):
        network_info = dict(nova_net_id=net_name)
        instance = service_instance.NovaNetworkHelper(self.fake_manager)

        self.assertRaises(
            exception.ManilaException, instance.get_network_name, network_info)

    def test_setup_network(self):
        network_info = dict(nova_net_id='fake_nova_net_id')
        network = dict(label='fake_network', id='fake_network_id',
                       gateway='fake_gateway_ip')
        instance = service_instance.NovaNetworkHelper(self.fake_manager)
        self.mock_object(instance.compute_api, 'network_get',
                         mock.Mock(return_value=network))
        expected = dict(
            nova_net_id=network_info['nova_net_id'],
            nics=[{'net-id': network['id']}],
            service_ip='fake_gateway_ip')

        result = instance.setup_network(network_info)

        self.assertEqual(expected, result)
        instance.compute_api.network_get.assert_called_once_with(
            instance.admin_context, network_info['nova_net_id'])

    @ddt.data(None, [], {}, '')
    def test_setup_network_invalid(self, net_name):
        network_info = dict(nova_net_id=net_name)
        instance = service_instance.NovaNetworkHelper(self.fake_manager)

        self.assertRaises(
            exception.ManilaException, instance.get_network_name, network_info)
