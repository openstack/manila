# Copyright 2015, Hitachi Data Systems.
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

import sys

from manila.cmd import data as manila_data
from manila import test
from manila import version

CONF = manila_data.CONF


class ManilaCmdDataTestCase(test.TestCase):

    def test_main(self):
        sys.argv = ['manila-data']
        self.mock_object(manila_data.log, 'setup')
        self.mock_object(manila_data.log, 'register_options')
        self.mock_object(manila_data.utils, 'monkey_patch')
        self.mock_object(manila_data.service.Service, 'create')
        self.mock_object(manila_data.service, 'serve')
        self.mock_object(manila_data.service, 'wait')

        manila_data.main()

        self.assertEqual('manila', CONF.project)
        self.assertEqual(version.version_string(), CONF.version)
        manila_data.log.setup.assert_called_once_with(CONF, "manila")
        manila_data.log.register_options.assert_called_once_with(CONF)
        manila_data.utils.monkey_patch.assert_called_once_with()
        manila_data.service.Service.create.assert_called_once_with(
            binary='manila-data')
        manila_data.service.wait.assert_called_once_with()
        manila_data.service.serve.assert_called_once_with(
            manila_data.service.Service.create.return_value)
