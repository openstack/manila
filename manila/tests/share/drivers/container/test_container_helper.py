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
import uuid

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

    def test_start_container(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(return_value=['fake_output', '']))
        uuid.uuid1 = mock.Mock(return_value='')
        expected = ['docker', 'run', '-d', '-i', '-t', '--privileged', '-v',
                    '/dev:/dev', '--name=manila_cifs_docker_container', '-v',
                    '/tmp/shares:/shares', 'fake_image']

        self.DockerExecHelper.start_container()

        self.DockerExecHelper._inner_execute.assert_called_once_with(expected)

    def test_start_container_impossible_failure(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(side_effect=OSError()))

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.start_container)

    def test_stop_container(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(return_value=['fake_output', '']))
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

    @ddt.data(('inet',
               "192.168.0.254",
               ["5: br0 inet 192.168.0.254/24 brd 192.168.0.255 "
                "scope global br0 valid_lft forever preferred_lft forever"]),
              ("inet6",
               "2001:470:8:c82:6600:6aff:fe84:8dda",
               ["5: br0 inet6 2001:470:8:c82:6600:6aff:fe84:8dda/64 "
                "scope global valid_lft forever preferred_lft forever"]),
              )
    @ddt.unpack
    def test_fetch_container_address(self, address_family, expected_address,
                                     return_value):
        fake_name = "fakeserver"
        mock_execute = self.DockerExecHelper.execute = mock.Mock(
            return_value=return_value)

        address = self.DockerExecHelper.fetch_container_address(
            fake_name,
            address_family)

        self.assertEqual(expected_address, address)
        mock_execute.assert_called_once_with(
            fake_name, ["ip", "-oneline", "-family", address_family, "address",
                        "show", "scope", "global", "dev", "eth0"]
        )

    def test_rename_container(self):

        fake_old_name = "old_name"
        fake_new_name = "new_name"
        fake_veth_name = "veth_fake"
        self.DockerExecHelper.find_container_veth = mock.Mock(
            return_value=fake_veth_name)
        mock__inner_execute = self.DockerExecHelper._inner_execute = mock.Mock(
            return_value=['fake', ''])

        self.DockerExecHelper.rename_container(fake_old_name, fake_new_name)
        self.DockerExecHelper.find_container_veth.assert_called_once_with(
            fake_old_name
        )
        mock__inner_execute.assert_has_calls([
            mock.call(["docker", "rename", fake_old_name, fake_new_name]),
            mock.call(["ovs-vsctl", "set", "interface", fake_veth_name,
                      "external-ids:manila-container=%s" % fake_new_name])
        ])

    def test_rename_container_exception_veth(self):

        self.DockerExecHelper.find_container_veth = mock.Mock(
            return_value=None)

        self.assertRaises(exception.ManilaException,
                          self.DockerExecHelper.rename_container,
                          "old_name", "new_name")

    @ddt.data([['fake', ''], OSError, ['fake', '']],
              [['fake', ''], OSError, OSError],
              [OSError])
    def test_rename_container_exception_cmds(self, side_effect):
        fake_old_name = "old_name"
        fake_new_name = "new_name"
        fake_veth_name = "veth_fake"

        self.DockerExecHelper.find_container_veth = mock.Mock(
            return_value=fake_veth_name)
        mock__inner_execute = self.DockerExecHelper._inner_execute = mock.Mock(
            side_effect=side_effect)

        self.assertRaises(exception.ShareBackendException,
                          self.DockerExecHelper.rename_container,
                          fake_old_name, fake_new_name)

        if len(side_effect) > 1:
            mock__inner_execute.assert_has_calls([
                mock.call(["docker", "rename", fake_old_name, fake_new_name]),
                mock.call(["ovs-vsctl", "set", "interface", fake_veth_name,
                           "external-ids:manila-container=%s" % fake_new_name])
            ])
        else:
            mock__inner_execute.assert_has_calls([
                mock.call(["docker", "rename", fake_old_name, fake_new_name]),
            ])

    @ddt.data('my_container', 'manila_my_container')
    def test_find_container_veth(self, name):

        interfaces = [fakes.FAKE_VSCTL_LIST_INTERFACE_1,
                      fakes.FAKE_VSCTL_LIST_INTERFACE_2,
                      fakes.FAKE_VSCTL_LIST_INTERFACE_4]

        if 'manila_' in name:
            list_interfaces = [fakes.FAKE_VSCTL_LIST_INTERFACES]
            interfaces.append(fakes.FAKE_VSCTL_LIST_INTERFACE_3)
        else:
            list_interfaces = [fakes.FAKE_VSCTL_LIST_INTERFACES_X]
            interfaces.append(fakes.FAKE_VSCTL_LIST_INTERFACE_3_X)

        def get_interface_data_according_to_veth(*args, **kwargs):
            if len(args) == 4:
                for interface in interfaces:
                    if args[3] in interface:
                        return [interface]
            else:
                return list_interfaces

        self.DockerExecHelper._execute = mock.Mock(
            side_effect=get_interface_data_according_to_veth)

        result = self.DockerExecHelper.find_container_veth(name)

        self.assertEqual("veth3jd83j7", result)

    @ddt.data(True, False)
    def test_find_container_veth_not_found(self, remove_veth):

        if remove_veth:
            list_executes = [[fakes.FAKE_VSCTL_LIST_INTERFACES],
                             [fakes.FAKE_VSCTL_LIST_INTERFACE_1],
                             OSError,
                             [fakes.FAKE_VSCTL_LIST_INTERFACE_3],
                             [fakes.FAKE_VSCTL_LIST_INTERFACE_4]]
        else:
            list_executes = [[fakes.FAKE_VSCTL_LIST_INTERFACES],
                             [fakes.FAKE_VSCTL_LIST_INTERFACE_1],
                             [fakes.FAKE_VSCTL_LIST_INTERFACE_2],
                             [fakes.FAKE_VSCTL_LIST_INTERFACE_3],
                             [fakes.FAKE_VSCTL_LIST_INTERFACE_4]]

        self.DockerExecHelper._execute = mock.Mock(
            side_effect=list_executes)
        list_veths = ['veth11b2c34', 'veth25f6g7h', 'veth3jd83j7',
                      'veth4i9j10k']

        self.assertIsNone(
            self.DockerExecHelper.find_container_veth("foo_bar"))
        list_calls = [mock.call("ovs-vsctl", "list", "interface",
                                run_as_root=True)]

        for veth in list_veths:
            list_calls.append(
                mock.call("ovs-vsctl", "list", "interface", veth,
                          run_as_root=True)
            )

        self.DockerExecHelper._execute.assert_has_calls(
            list_calls, any_order=True
        )

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
