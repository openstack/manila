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

from manila.cmd import share as manila_share
from manila import test

CONF = manila_share.CONF


@ddt.ddt
class ManilaCmdShareTestCase(test.TestCase):

    @ddt.data(None, [], ['foo', ], ['foo', 'bar', ])
    def test_main(self, backends):
        self.mock_object(manila_share.log, 'setup')
        self.mock_object(manila_share.log, 'register_options')
        self.mock_object(manila_share.utils, 'monkey_patch')
        self.mock_object(manila_share.service, 'process_launcher')
        self.mock_object(manila_share.service.Service, 'create')
        self.launcher = manila_share.service.process_launcher.return_value
        self.mock_object(self.launcher, 'launch_service')
        self.mock_object(self.launcher, 'wait')
        self.server = manila_share.service.Service.create.return_value
        fake_host = 'fake_host'
        CONF.set_override('enabled_share_backends', backends)
        CONF.set_override('host', fake_host)
        sys.argv = ['manila-share']

        manila_share.main()

        manila_share.log.setup.assert_called_once_with(CONF, "manila")
        manila_share.log.register_options.assert_called_once_with(CONF)
        manila_share.utils.monkey_patch.assert_called_once_with()
        manila_share.service.process_launcher.assert_called_once_with()
        self.launcher.wait.assert_called_once_with()

        if backends:
            manila_share.service.Service.create.assert_has_calls([
                mock.call(
                    host=fake_host + '@' + backend,
                    service_name=backend,
                    binary='manila-share') for backend in backends
            ])
            self.launcher.launch_service.assert_has_calls([
                mock.call(self.server) for backend in backends])
        else:
            manila_share.service.Service.create.assert_called_once_with(
                binary='manila-share')
            self.launcher.launch_service.assert_called_once_with(self.server)
