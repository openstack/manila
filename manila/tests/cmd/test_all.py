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

import ddt
import mock
from oslo_log import log

from manila.cmd import all as manila_all
from manila import service
from manila import test
from manila import utils
from manila import version

CONF = manila_all.CONF


@ddt.ddt
class ManilaCmdAllTestCase(test.TestCase):
    def setUp(self):
        super(ManilaCmdAllTestCase, self).setUp()
        sys.argv = ['manila-all']

        self.mock_object(log, 'setup')
        self.mock_object(log, 'register_options')
        self.mock_object(log, 'getLogger')
        self.mock_object(utils, 'monkey_patch')
        self.mock_object(service, 'WSGIService')
        self.mock_object(service.Service, 'create')
        self.mock_object(service, 'serve')
        self.mock_object(service, 'wait')
        self.wsgi_service = service.WSGIService.return_value
        self.service = service.Service.create.return_value
        self.fake_log = log.getLogger.return_value

    def _common_checks(self):
        self.assertEqual(CONF.project, 'manila')
        self.assertEqual(CONF.version, version.version_string())
        log.setup.assert_called_once_with(CONF, "manila")
        log.register_options.assert_called_once_with(CONF)
        log.getLogger.assert_called_once_with('manila.all')
        utils.monkey_patch.assert_called_once_with()
        service.WSGIService.assert_called_once_with('osapi_share')
        service.wait.assert_called_once_with()

    def test_main(self):
        manila_all.main()

        self._common_checks()
        self.assertFalse(self.fake_log.exception.called)
        service.serve.assert_has_calls([
            mock.call(self.wsgi_service, *[self.service] * 3)
        ])

    @ddt.data(Exception(), SystemExit())
    def test_main_wsgi_service_osapi_share_exception(self, exc):
        service.WSGIService.side_effect = exc

        manila_all.main()

        self._common_checks()
        self.fake_log.exception.assert_called_once_with(mock.ANY)
        service.serve.assert_has_calls([mock.call(*[self.service] * 3)])

    @ddt.data(Exception(), SystemExit())
    def test_main_service_create_exception(self, exc):
        service.Service.create.side_effect = exc

        manila_all.main()

        self._common_checks()
        self.fake_log.exception.assert_has_calls(mock.ANY)
        service.serve.assert_has_calls([mock.call(self.wsgi_service)])
