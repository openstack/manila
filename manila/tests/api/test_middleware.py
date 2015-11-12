# Copyright (c) 2015 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

import ddt
from oslo_config import cfg

from manila.tests.integrated import integrated_helpers


@ddt.ddt
class TestCORSMiddleware(integrated_helpers._IntegratedTestBase):
    '''Provide a basic smoke test to ensure CORS middleware is active.

    The tests below provide minimal confirmation that the CORS middleware
    is active, and may be configured. For comprehensive tests, please consult
    the test suite in oslo_middleware.
    '''

    def setUp(self):
        # Here we monkeypatch GroupAttr.__getattr__, necessary because the
        # paste.ini method of initializing this middleware creates its own
        # ConfigOpts instance, bypassing the regular config fixture.
        # Mocking also does not work, as accessing an attribute on a mock
        # object will return a MagicMock instance, which will fail
        # configuration type checks.
        def _mock_getattr(instance, key):
            if key != 'allowed_origin':
                return self._original_call_method(instance, key)
            return "http://valid.example.com"

        self._original_call_method = cfg.ConfigOpts.GroupAttr.__getattr__
        cfg.ConfigOpts.GroupAttr.__getattr__ = _mock_getattr

        # Initialize the application after all the config overrides are in
        # place.
        super(TestCORSMiddleware, self).setUp()

    def tearDown(self):
        super(TestCORSMiddleware, self).tearDown()

        # Reset the configuration overrides.
        cfg.ConfigOpts.GroupAttr.__getattr__ = self._original_call_method

    @ddt.data(
        ('http://valid.example.com', 'http://valid.example.com'),
        ('http://invalid.example.com', None),
    )
    @ddt.unpack
    def test_options_request(self, origin_url, acao_header_expected):
        response = self.api.api_request(
            '',
            method='OPTIONS',
            headers={
                'Origin': origin_url,
                'Access-Control-Request-Method': 'GET',
            }
        )
        self.assertEqual(200, response.status)
        self.assertEqual(acao_header_expected,
                         response.getheader('Access-Control-Allow-Origin'))

    @ddt.data(
        ('http://valid.example.com', 'http://valid.example.com'),
        ('http://invalid.example.com', None),
    )
    @ddt.unpack
    def test_get_request(self, origin_url, acao_header_expected):
        response = self.api.api_request(
            '',
            method='GET',
            headers={
                'Origin': origin_url
            }
        )
        self.assertEqual(404, response.status)
        self.assertEqual(acao_header_expected,
                         response.getheader('Access-Control-Allow-Origin'))
