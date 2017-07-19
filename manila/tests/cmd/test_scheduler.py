# Copyright 2015 Mirantis Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sys

from manila.cmd import scheduler as manila_scheduler
from manila import test
from manila import version

CONF = manila_scheduler.CONF


class ManilaCmdSchedulerTestCase(test.TestCase):

    def test_main(self):
        sys.argv = ['manila-scheduler']
        self.mock_object(manila_scheduler.log, 'setup')
        self.mock_object(manila_scheduler.log, 'register_options')
        self.mock_object(manila_scheduler.utils, 'monkey_patch')
        self.mock_object(manila_scheduler.service.Service, 'create')
        self.mock_object(manila_scheduler.service, 'serve')
        self.mock_object(manila_scheduler.service, 'wait')

        manila_scheduler.main()

        self.assertEqual('manila', CONF.project)
        self.assertEqual(version.version_string(), CONF.version)
        manila_scheduler.log.setup.assert_called_once_with(CONF, "manila")
        manila_scheduler.log.register_options.assert_called_once_with(CONF)
        manila_scheduler.utils.monkey_patch.assert_called_once_with()
        manila_scheduler.service.Service.create.assert_called_once_with(
            binary='manila-scheduler', coordination=True)
        manila_scheduler.service.wait.assert_called_once_with()
        manila_scheduler.service.serve.assert_called_once_with(
            manila_scheduler.service.Service.create.return_value)
