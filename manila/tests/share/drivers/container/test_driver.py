# Copyright 2016 Mirantis, Inc.
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
"""Unit tests for the Container driver module."""

import ddt
import functools
import mock
from oslo_config import cfg

from manila.common import constants as const
from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers.container import driver
from manila.share.drivers.container import protocol_helper
from manila import test
from manila.tests import fake_utils
from manila.tests.share.drivers.container import fakes as cont_fakes


CONF = cfg.CONF
CONF.import_opt('lvm_share_export_ip', 'manila.share.drivers.lvm')


@ddt.ddt
class ContainerShareDriverTestCase(test.TestCase):
    """Tests ContainerShareDriver"""

    def setUp(self):
        super(ContainerShareDriverTestCase, self).setUp()
        fake_utils.stub_out_utils_execute(self)
        self._context = context.get_admin_context()
        self._db = mock.Mock()
        self.fake_conf = configuration.Configuration(None)

        CONF.set_default('driver_handles_share_servers', True)

        self._driver = driver.ContainerShareDriver(
            configuration=self.fake_conf)

        self.share = cont_fakes.fake_share()
        self.access = cont_fakes.fake_access()
        self.server = {
            'public_address': self.fake_conf.lvm_share_export_ip,
            'instance_id': 'LVM',
        }

        # Used only to test compatibility with share manager
        self.share_server = "fake_share_server"

    def fake_exec_sync(self, *args, **kwargs):
        kwargs['execute_arguments'].append(args)
        try:
            ret_val = kwargs['ret_val']
        except KeyError:
            ret_val = None
        return ret_val

    def test__get_helper_ok(self):
        share = cont_fakes.fake_share(share_proto='CIFS')
        expected = protocol_helper.DockerCIFSHelper(None)

        actual = self._driver._get_helper(share)

        self.assertEqual(type(expected), type(actual))

    def test__get_helper_existing_ok(self):
        share = cont_fakes.fake_share(share_proto='CIFS')
        expected = protocol_helper.DockerCIFSHelper
        self._driver._helpers = {'CIFS': expected}

        actual = self._driver._get_helper(share)

        self.assertEqual(expected, type(actual))

    def test__get_helper_not_ok(self):
        share = cont_fakes.fake_share()

        self.assertRaises(exception.InvalidShare, self._driver._get_helper,
                          share)

    def test_update_share_stats(self):
        self.mock_object(self._driver.storage, 'get_share_server_pools',
                         mock.Mock(return_value='test-pool'))

        self._driver._update_share_stats()

        self.assertEqual('Docker', self._driver._stats['share_backend_name'])
        self.assertEqual('CIFS', self._driver._stats['storage_protocol'])
        self.assertEqual(0, self._driver._stats['reserved_percentage'])
        self.assertIsNone(self._driver._stats['consistency_group_support'])
        self.assertEqual(False, self._driver._stats['snapshot_support'])
        self.assertEqual('ContainerShareDriver',
                         self._driver._stats['driver_name'])
        self.assertEqual('test-pool', self._driver._stats['pools'])
        self.assertTrue(self._driver._stats['ipv4_support'])
        self.assertFalse(self._driver._stats['ipv6_support'])

    def test_create_share(self):
        helper = mock.Mock()
        self.mock_object(helper, 'create_share',
                         mock.Mock(return_value='export_location'))
        self.mock_object(self._driver, "_get_helper",
                         mock.Mock(return_value=helper))
        self.mock_object(self._driver.storage, 'provide_storage')
        self.mock_object(self._driver.container, 'execute')

        self.assertEqual('export_location',
                         self._driver.create_share(self._context, self.share,
                                                   {'id': 'fake'}))

    def test_delete_share_ok(self):
        helper = mock.Mock()
        self.mock_object(self._driver, "_get_helper",
                         mock.Mock(return_value=helper))
        self.mock_object(self._driver.container, 'execute')
        self.mock_object(self._driver.storage, 'remove_storage')

        self._driver.delete_share(self._context, self.share, {'id': 'fake'})

        self._driver.container.execute.assert_called_with(
            'manila_fake',
            ['rm', '-fR', '/shares/fakeshareid']
            )

    def test_delete_share_rm_fails(self):
        def fake_execute(*args):
            if 'rm' in args[1]:
                raise exception.ProcessExecutionError()
        self.mock_object(driver.LOG, "warning")
        self.mock_object(self._driver, "_get_helper")
        self.mock_object(self._driver.container, "execute", fake_execute)
        self.mock_object(self._driver.storage, 'remove_storage')

        self._driver.delete_share(self._context, self.share, {'id': 'fake'})

        self.assertTrue(driver.LOG.warning.called)

    def test_extend_share(self):
        share = cont_fakes.fake_share()
        actual_arguments = []
        expected_arguments = [
            ('manila_fake_server', ['umount', '/shares/fakeshareid']),
            ('manila_fake_server',
             ['mount', '/dev/manila_docker_volumes/fakeshareid',
              '/shares/fakeshareid'])
        ]
        self.mock_object(self._driver.storage, "extend_share")
        self._driver.container.execute = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val='')

        self._driver.extend_share(share, 2, {'id': 'fake-server'})

        self.assertEqual(expected_arguments, actual_arguments)

    def test_ensure_share(self):
        # Does effectively nothing by design.
        self.assertEqual(1, 1)

    def test_update_access_access_rules_ok(self):
        helper = mock.Mock()
        self.mock_object(self._driver, "_get_helper",
                         mock.Mock(return_value=helper))

        self._driver.update_access(self._context, self.share,
                                   [{'access_level': const.ACCESS_LEVEL_RW}],
                                   [], [], {"id": "fake"})

        helper.update_access.assert_called_with('manila_fake',
                                                [{'access_level': 'rw'}],
                                                [], [])

    def test_get_network_allocation_numer(self):
        # Does effectively nothing by design.
        self.assertEqual(1, self._driver.get_network_allocations_number())

    def test__get_container_name(self):
        self.assertEqual("manila_fake_server",
                         self._driver._get_container_name("fake-server"))

    def test_do_setup(self):
        # Does effectively nothing by design.
        self.assertEqual(1, 1)

    def test_check_for_setup_error_host_not_ok_class_ok(self):
        setattr(self._driver.configuration.local_conf,
                'neutron_host_id', None)

        self.assertRaises(exception.ManilaException,
                          self._driver.check_for_setup_error)

    def test_check_for_setup_error_host_not_ok_class_some_other(self):
        setattr(self._driver.configuration.local_conf,
                'neutron_host_id', None)
        setattr(self._driver.configuration.local_conf,
                'network_api_class',
                'manila.share.drivers.container.driver.ContainerShareDriver')
        self.mock_object(driver.LOG, "warning")

        self._driver.check_for_setup_error()

        setattr(self._driver.configuration.local_conf,
                'network_api_class',
                'manila.network.neutron.neutron_network_plugin.'
                'NeutronNetworkPlugin')

        self.assertTrue(driver.LOG.warning.called)

    def test__connect_to_network(self):
        network_info = cont_fakes.fake_network()
        helper = mock.Mock()
        self.mock_object(self._driver, "_execute",
                         mock.Mock(return_value=helper))
        self.mock_object(self._driver.container, "execute")

        self._driver._connect_to_network("fake-server", network_info,
                                         "fake-veth")

    @ddt.data(['veth0000000'], ['veth0000000' * 2])
    def test__teardown_server(self, list_of_veths):
        def fake_ovs_execute(*args, **kwargs):
            kwargs['arguments'].append(args)
            if len(args) == 3:
                return list_of_veths
            elif len(args) == 4:
                return ('fake:manila_b5afb5c1_6011_43c4_8a37_29820e6951a7', '')
            else:
                return 0
        actual_arguments = []
        expected_arguments = [
            ('ovs-vsctl', 'list', 'interface'),
            ('ovs-vsctl', 'list', 'interface', 'veth0000000'),
            ('ovs-vsctl', '--', 'del-port', 'br-int', 'veth0000000')
        ]
        self.mock_object(self._driver.container, "stop_container", mock.Mock())
        self._driver._execute = functools.partial(
            fake_ovs_execute, arguments=actual_arguments)

        self._driver._teardown_server(
            server_details={"id": "b5afb5c1-6011-43c4-8a37-29820e6951a7"})

        self.assertEqual(expected_arguments.sort(), actual_arguments.sort())

    @ddt.data(['veth0000000'], ['veth0000000' * 2])
    def test__teardown_server_veth_disappeared_mysteriously(self,
                                                            list_of_veths):
        def fake_ovs_execute(*args, **kwargs):
            if len(args) == 3:
                return list_of_veths
            if len(args) == 4:
                return ('fake:manila_b5afb5c1_6011_43c4_8a37_29820e6951a7', '')
            if 'del-port' in args:
                raise exception.ProcessExecutionError()
            else:
                return 0
        self.mock_object(driver.LOG, "warning")
        self.mock_object(self._driver, "_execute", fake_ovs_execute)

        self._driver._teardown_server(
            server_details={"id": "b5afb5c1-6011-43c4-8a37-29820e6951a7"})

        self.assertTrue(driver.LOG.warning.called)

    @ddt.data(['veth0000000'], ['veth0000000' * 2])
    def test__teardown_server_check_continuation(self, list_of_veths):
        def fake_ovs_execute(*args, **kwargs):
            kwargs['arguments'].append(args)
            if len(args) == 3:
                return list_of_veths
            elif len(args) == 4:
                return ('fake:', '')
            else:
                return 0
        actual_arguments = []
        expected_arguments = [
            ('ovs-vsctl', 'list', 'interface'),
            ('ovs-vsctl', 'list', 'interface', 'veth0000000'),
            ('ovs-vsctl', '--', 'del-port', 'br-int', 'veth0000000')
        ]
        self.mock_object(self._driver.container, "stop_container", mock.Mock())
        self._driver._execute = functools.partial(
            fake_ovs_execute, arguments=actual_arguments)

        self._driver._teardown_server(
            server_details={"id": "b5afb5c1-6011-43c4-8a37-29820e6951a7"})

        self.assertEqual(expected_arguments.sort(), actual_arguments.sort())

    def test__get_veth_state(self):
        retval = ('veth0000000\n', '')
        self.mock_object(self._driver, "_execute",
                         mock.Mock(return_value=retval))

        result = self._driver._get_veth_state()

        self.assertEqual(['veth0000000'], result)

    def test__get_corresponding_veth_ok(self):
        before = ['veth0000000']
        after = ['veth0000000', 'veth0000001']

        result = self._driver._get_corresponding_veth(before, after)

        self.assertEqual('veth0000001', result)

    def test__get_corresponding_veth_raises(self):
        before = ['veth0000000']
        after = ['veth0000000', 'veth0000001', 'veth0000002']

        self.assertRaises(exception.ManilaException,
                          self._driver._get_corresponding_veth,
                          before, after)

    def test__setup_server_container_fails(self):
        network_info = cont_fakes.fake_network()
        self.mock_object(self._driver.container, 'start_container')
        self._driver.container.start_container.side_effect = KeyError()

        self.assertRaises(exception.ManilaException,
                          self._driver._setup_server, network_info)

    def test__setup_server_ok(self):
        network_info = cont_fakes.fake_network()
        server_id = self._driver._get_container_name(network_info["server_id"])
        self.mock_object(self._driver.container, 'start_container')
        self.mock_object(self._driver, '_get_veth_state')
        self.mock_object(self._driver, '_get_corresponding_veth',
                         mock.Mock(return_value='veth0'))
        self.mock_object(self._driver, '_connect_to_network')

        self.assertEqual(network_info['server_id'],
                         self._driver._setup_server(network_info)['id'])
        self._driver.container.start_container.assert_called_once_with(
            server_id)
        self._driver._connect_to_network.assert_called_once_with(server_id,
                                                                 network_info,
                                                                 'veth0')
