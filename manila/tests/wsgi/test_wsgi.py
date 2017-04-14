# Copyright 2017 Mirantis Inc.
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

import mock

from manila import test
from manila.wsgi import wsgi


class WSGITestCase(test.TestCase):

    def test_initialize_application(self):
        self.mock_object(wsgi.log, 'register_options')
        self.mock_object(wsgi.cfg.ConfigOpts, '__call__')
        self.mock_object(wsgi.config, 'verify_share_protocols')
        self.mock_object(wsgi.log, 'setup')
        self.mock_object(wsgi.rpc, 'init')
        self.mock_object(wsgi.wsgi, 'Loader')
        wsgi.sys.argv = ['--verbose', '--debug']

        result = wsgi.initialize_application()

        self.assertEqual(
            wsgi.wsgi.Loader.return_value.load_app.return_value, result)
        wsgi.log.register_options.assert_called_once_with(mock.ANY)
        wsgi.cfg.ConfigOpts.__call__.assert_called_once_with(
            mock.ANY, project="manila", version=wsgi.version.version_string())
        wsgi.config.verify_share_protocols.assert_called_once_with()
        wsgi.log.setup.assert_called_once_with(mock.ANY, "manila")
        wsgi.rpc.init.assert_called_once_with(mock.ANY)
        wsgi.wsgi.Loader.assert_called_once_with(mock.ANY)
        wsgi.wsgi.Loader.return_value.load_app.assert_called_once_with(
            name='osapi_share')
