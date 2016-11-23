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

import mock
import uuid

from manila import exception
from manila.share import configuration
from manila.share.drivers.container import container_helper
from manila import test


class DockerExecHelperTestCase(test.TestCase):
    """Tests DockerExecHelper"""

    def setUp(self):
        super(DockerExecHelperTestCase, self).setUp()
        self.fake_conf = configuration.Configuration(None)
        self.fake_conf.container_image_name = "fake_image"
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
                         mock.Mock(return_value=['', 'but how?!']))

        self.assertRaises(exception.ManilaException,
                          self.DockerExecHelper.start_container)

    def test_stop_container(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(return_value=['fake_output', '']))
        expected = ['docker', 'stop', 'manila-fake-conainer']

        self.DockerExecHelper.stop_container("manila-fake-conainer")

        self.DockerExecHelper._inner_execute.assert_called_once_with(expected)

    def test_stop_container_oh_noes(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(return_value=['fake_output',
                                                 'fake_problem']))

        self.assertRaises(exception.ManilaException,
                          self.DockerExecHelper.stop_container,
                          "manila-fake-container")

    def test_execute(self):
        self.mock_object(self.DockerExecHelper, "_inner_execute",
                         mock.Mock(return_value='fake_output'))
        expected = ['docker', 'exec', '-i', 'fake_container', 'fake_script']

        self.DockerExecHelper.execute("fake_container", ["fake_script"])

        self.DockerExecHelper._inner_execute.assert_called_once_with(expected)

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
        self.DockerExecHelper._execute = mock.Mock(return_value='fake')
        self.DockerExecHelper._execute.side_effect = KeyError()

        result = self.DockerExecHelper._inner_execute("fake_command")

        self.assertIsNone(result)
