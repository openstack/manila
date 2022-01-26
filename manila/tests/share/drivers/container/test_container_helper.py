# Copyright (c) 2016 Mirantis, Inc.
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
"""Unit tests for the Container helper module."""

from unittest import mock

import ddt

from manila import exception
from manila.share import configuration
from manila.share.drivers.container import container_helper
from manila import test
from manila.tests.share.drivers.container import fakes


@ddt.ddt
class DockerExecHelperTestCase(test.TestCase):
    """Tests DockerExecHelper"""

    def setUp(self):
        super(DockerExecHelperTestCase, self).setUp()
        self.fake_conf = configuration.Configuration(None)
        self.fake_conf.container_image_name = "fake_image"
        self.fake_conf.container_volume_mount_path = "/tmp/shares"
        self.DockerExecHelper = container_helper.DockerExecHelper(
            configuration=self.fake_conf)

    def test_create_container(self):
        fake_name = 'fake_container'
        self.DockerExecHelper.configuration.container_image_name = 'fake_image'

        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(return_value=('fake_container_id', '')))
        self.mock_object(self.DockerExecHelper, 'disconnect_network')

        self.DockerExecHelper.create_container(fake_name)

        self.DockerExecHelper._inner_execute.assert_called_once_with([
            'docker', 'container', 'create', '--name=%s' % fake_name,
            '--privileged', '-v', '/dev:/dev', '-v', '/tmp/shares:/shares',
            'fake_image'])
        self.DockerExecHelper.disconnect_network.assert_called_once_with(
            'bridge', fake_name)

    def test_create_container_failure(self):
        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(side_effect=OSError()))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.create_container)

    def test_start_container(self):
        fake_name = 'fake_container'

        self.mock_object(self.DockerExecHelper, '_inner_execute', mock.Mock())

        self.DockerExecHelper.start_container(fake_name)

        self.DockerExecHelper._inner_execute.assert_called_once_with([
            'docker', 'container', 'start', 'fake_container'])

    def test_start_container_impossible_failure(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(side_effect=OSError()))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.start_container, None)

    def test_stop_container(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(return_value=['fake_output', None]))
        expected = ['docker', 'stop', 'manila-fake-conainer']

        self.DockerExecHelper.stop_container("manila-fake-conainer")

        self.DockerExecHelper._inner_execute.assert_called_once_with(expected)

    def test_stop_container_oh_noes(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(side_effect=OSError))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.stop_container,
                          "manila-fake-container")

    def test_execute(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(return_value='fake_output'))
        expected = ['docker', 'exec', '-i', 'fake_container', 'fake_script']

        self.DockerExecHelper.execute("fake_container", ["fake_script"])

        self.DockerExecHelper._inner_execute.assert_called_once_with(
            expected, ignore_errors=False)

    def test_execute_name_not_there(self):
        self.assertRaises(exception.ManilaException,
                          self.DockerExecHelper.execute,
                          None, ['do', 'stuff'])

    def test_execute_command_not_there(self):
        self.assertRaises(exception.ManilaException,
                          self.DockerExecHelper.execute,
                          'fake-name', None)

    def test_execute_bad_command_format(self):
        self.assertRaises(exception.ManilaException,
                          self.DockerExecHelper.execute,
                          'fake-name', 'do stuff')

    def test__inner_execute_ok(self):
        self.DockerExecHelper._execute = mock.Mock(return_value='fake')

        result = self.DockerExecHelper._inner_execute("fake_command")

        self.assertEqual(result, 'fake')

    def test__inner_execute_not_ok(self):
        self.DockerExecHelper._execute = mock.Mock(side_effect=[OSError()])

        self.assertRaises(OSError,
                          self.DockerExecHelper._inner_execute, "fake_command")

    def test__inner_execute_not_ok_ignore_errors(self):
        self.DockerExecHelper._execute = mock.Mock(side_effect=OSError())

        result = self.DockerExecHelper._inner_execute("fake_command",
                                                      ignore_errors=True)

        self.assertIsNone(result)

    def test_fetch_container_addresses(self):
        fake_name = 'fake_container'
        fake_addresses = ['192.168.144.19', '10.0.0.131']
        fake_ip_addr_show = fakes.FAKE_IP_ADDR_SHOW
        fake_interfaces = ['eth0', 'eth1']

        self.mock_object(self.DockerExecHelper, 'fetch_container_interfaces',
                         mock.Mock(return_value=fake_interfaces))
        self.mock_object(self.DockerExecHelper, 'execute',
                         mock.Mock(side_effect=[fake_ip_addr_show[0],
                                                fake_ip_addr_show[1]]))

        self.assertEqual(fake_addresses,
                         self.DockerExecHelper.fetch_container_addresses(
                             fake_name, 'inet'))
        (self.DockerExecHelper.fetch_container_interfaces
         .assert_called_once_with(fake_name))
        self.DockerExecHelper.execute.assert_any_call(
            fake_name, ['ip', '-oneline', '-family', 'inet', 'address',
                        'show', 'scope', 'global', 'dev', 'eth0']
        )
        self.DockerExecHelper.execute.assert_any_call(
            fake_name, ['ip', '-oneline', '-family', 'inet', 'address',
                        'show', 'scope', 'global', 'dev', 'eth1']
        )

    def test_fetch_container_interfaces(self):
        fake_name = 'fake_container'
        fake_eths = fakes.FAKE_IP_LINK_SHOW

        self.mock_object(self.DockerExecHelper, 'execute',
                         mock.Mock(return_value=fake_eths))

        self.assertEqual(
            ['eth0', 'eth1'],
            self.DockerExecHelper.fetch_container_interfaces(fake_name))
        self.DockerExecHelper.execute.assert_called_once_with(
            fake_name, ['ip', '-o', 'link', 'show'])

    def test_rename_container(self):
        fake_old_name = 'old_name'
        fake_new_name = 'new_name'
        fake_veth_names = ['fake_veth']

        self.mock_object(self.DockerExecHelper, 'get_container_veths',
                         mock.Mock(return_value=fake_veth_names))
        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(side_effect=[None, None]))

        self.DockerExecHelper.rename_container(fake_old_name, fake_new_name)

        self.DockerExecHelper.get_container_veths.assert_called_once_with(
            fake_old_name)
        self.DockerExecHelper._inner_execute.assert_has_calls([
            mock.call(['docker', 'rename', fake_old_name, fake_new_name]),
            mock.call(['ovs-vsctl', 'set', 'interface', fake_veth_names[0],
                       'external-ids:manila-container=%s' % fake_new_name])])

    def test_rename_container_exception_veth(self):
        fake_old_name = 'old_name'
        fake_new_name = 'new_name'

        self.mock_object(self.DockerExecHelper, 'get_container_veths',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.ManilaException,
                          self.DockerExecHelper.rename_container,
                          fake_old_name, fake_new_name)

    @ddt.data([['fake', ''], OSError, ['fake', '']],
              [['fake', ''], OSError, OSError],
              [OSError])
    def test_rename_container_exception_cmds(self, side_effect):
        fake_old_name = 'old_name'
        fake_new_name = 'new_name'
        fake_veth_names = ['fake_veth']

        self.mock_object(self.DockerExecHelper, 'get_container_veths',
                         mock.Mock(return_value=fake_veth_names))
        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(side_effect=side_effect))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.rename_container,
                          fake_old_name, fake_new_name)

        if len(side_effect) > 1:
            self.DockerExecHelper._inner_execute.assert_has_calls([
                mock.call(['docker', 'rename', fake_old_name, fake_new_name]),
                mock.call(['ovs-vsctl', 'set', 'interface', fake_veth_names[0],
                           'external-ids:manila-container=%s' % fake_new_name])
            ])
        else:
            self.DockerExecHelper._inner_execute.assert_has_calls([
                mock.call(['docker', 'rename', fake_old_name, fake_new_name])])

    @ddt.data((["wrong_name\nfake\nfake_container\nfake_name'"], True),
              (["wrong_name\nfake_container\nfake'"], False),
              ("\n", False))
    @ddt.unpack
    def test_container_exists(self, fake_return_value, expected_result):

        self.DockerExecHelper._execute = mock.Mock(
            return_value=fake_return_value)

        result = self.DockerExecHelper.container_exists("fake_name")

        self.DockerExecHelper._execute.assert_called_once_with(
            "docker", "ps", "--no-trunc", "--format='{{.Names}}'",
            run_as_root=True)
        self.assertEqual(expected_result, result)

    def test_create_network(self):
        fake_network_name = 'fake_network_name'

        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(return_value=('fake_network_id', '')))

        self.DockerExecHelper.create_network(fake_network_name)

        self.DockerExecHelper._inner_execute.assert_called_once_with([
            'docker', 'network', 'create', fake_network_name])

    def test_create_network_failure(self):
        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(side_effect=OSError()))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.create_network, None)

    def test_remove_network(self):
        fake_network_name = 'fake_network_name'

        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(return_value=('fake_network_id', '')))

        self.DockerExecHelper.remove_network(fake_network_name)

        self.DockerExecHelper._inner_execute.assert_called_once_with([
            'docker', 'network', 'remove', fake_network_name])

    def test_remove_network_failure(self):
        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(side_effect=OSError()))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.remove_network, None)

    def test_connect_network(self):
        fake_network_name = 'fake_network_name'
        fake_server_id = 'fake_server_id'

        self.mock_object(self.DockerExecHelper, '_inner_execute')

        self.DockerExecHelper.connect_network(fake_network_name,
                                              fake_server_id)

        self.DockerExecHelper._inner_execute.assert_called_once_with([
            'docker', 'network', 'connect', fake_network_name, fake_server_id])

    def test_connect_network_failure(self):
        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(side_effect=OSError()))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.connect_network, None, None)

    def test_disconnect_network(self):
        fake_network_name = 'fake_network_name'
        fake_server_id = 'fake_server_id'

        self.mock_object(self.DockerExecHelper, '_inner_execute')

        self.DockerExecHelper.disconnect_network(fake_network_name,
                                                 fake_server_id)

        self.DockerExecHelper._inner_execute.assert_called_once_with([
            'docker', 'network', 'disconnect', fake_network_name,
            fake_server_id])

    def test_disconnect_network_failure(self):
        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(side_effect=OSError()))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.disconnect_network, None, None)

    def test_get_container_networks(self):
        fake_container_name = 'fake_container_name'
        fake_docker_inspect_networks = fakes.FAKE_DOCKER_INSPECT_NETWORKS
        fake_networks = ['fake_docker_network_0', 'fake_docker_network_1']

        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(return_value=fake_docker_inspect_networks))

        self.assertEqual(
            fake_networks,
            self.DockerExecHelper.get_container_networks(fake_container_name))
        self.DockerExecHelper._inner_execute.assert_called_once_with([
            'docker', 'container', 'inspect', '-f',
            '\'{{json .NetworkSettings.Networks}}\'', fake_container_name])

    def test_get_container_networks_failure(self):
        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(side_effect=OSError()))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.get_container_networks, None)

    def test_get_container_veths(self):
        fake_container_name = 'fake_container_name'
        fake_eths_iflinks = ('10\n11\n', '')
        fake_veths = ['fake_veth_0', 'fake_veth_1']

        self.mock_object(self.DockerExecHelper, 'execute',
                         mock.Mock(return_value=fake_eths_iflinks))
        self.mock_object(
            self.DockerExecHelper, '_execute',
            mock.Mock(side_effect=[('/sys/class/net/%s/ifindex'
                                    % fake_veths[0], ''),
                                   ('/sys/class/net/%s/ifindex'
                                    % fake_veths[1], '')]))

        self.assertEqual(
            fake_veths,
            self.DockerExecHelper.get_container_veths(fake_container_name))
        self.DockerExecHelper.execute.assert_called_once_with(
            fake_container_name,
            ['bash', '-c', 'cat /sys/class/net/eth*/iflink'])
        self.DockerExecHelper._execute.assert_has_calls([
            mock.call('bash', '-c', 'grep -l 10 /sys/class/net/veth*/ifindex'),
            mock.call('bash', '-c', 'grep -l 11 /sys/class/net/veth*/ifindex')
        ])

    def test_get_network_bridge(self):
        fake_network_name = 'fake_network_name'
        fake_network_id = ('012345abcdef', '')
        fake_bridge = 'br-' + fake_network_id[0]

        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(return_value=fake_network_id))

        self.assertEqual(
            fake_bridge,
            self.DockerExecHelper.get_network_bridge(fake_network_name))
        self.DockerExecHelper._inner_execute.assert_called_once_with([
            'docker', 'network', 'inspect', '-f', '{{.Id}}', fake_network_name
        ])

    def test_get_network_bridge_failure(self):
        self.mock_object(self.DockerExecHelper, '_inner_execute',
                         mock.Mock(side_effect=OSError()))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.get_network_bridge, None)

    def test_get_veth_from_bridge(self):
        fake_bridge = 'br-012345abcdef'
        fake_ip_link_show_master = fakes.FAKE_IP_LINK_SHOW_MASTER
        fake_veth = 'fake_veth'

        self.mock_object(self.DockerExecHelper, '_execute',
                         mock.Mock(return_value=fake_ip_link_show_master))

        self.assertEqual(
            fake_veth, self.DockerExecHelper.get_veth_from_bridge(fake_bridge))
        self.DockerExecHelper._execute.assert_called_once_with('ip', 'link',
                                                               'show',
                                                               'master',
                                                               fake_bridge)
