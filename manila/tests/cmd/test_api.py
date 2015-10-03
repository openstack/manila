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

from manila.cmd import api as manila_api
from manila import test
from manila import version

CONF = manila_api.CONF


class ManilaCmdApiTestCase(test.TestCase):
    def setUp(self):
        super(ManilaCmdApiTestCase, self).setUp()
        sys.argv = ['manila-api']

    def test_main(self):
        self.mock_object(manila_api.log, 'setup')
        self.mock_object(manila_api.log, 'register_options')
        self.mock_object(manila_api.utils, 'monkey_patch')
        self.mock_object(manila_api.service, 'process_launcher')
        self.mock_object(manila_api.service, 'WSGIService')

        manila_api.main()

        process_launcher = manila_api.service.process_launcher
        process_launcher.assert_called_once_with()
        self.assertTrue(process_launcher.return_value.launch_service.called)
        self.assertTrue(process_launcher.return_value.wait.called)
        self.assertEqual('manila', CONF.project)
        self.assertEqual(version.version_string(), CONF.version)
        manila_api.log.setup.assert_called_once_with(CONF, "manila")
        manila_api.log.register_options.assert_called_once_with(CONF)
        manila_api.utils.monkey_patch.assert_called_once_with()
        manila_api.service.WSGIService.assert_called_once_with('osapi_share')
