# Copyright 2015 Goutham Pacha Ravi
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

from tempest.api.share import base
from tempest import config_share as config
from tempest import test

CONF = config.CONF


class MicroversionsTest(base.BaseSharesTest):
    """Request and validate REST API Microversions.

    Sends a HTTP GET request with the base endpoint to request a Microversion.
    """

    _MIN_API_VERSION = CONF.share.min_api_microversion
    _MAX_API_VERSION = CONF.share.max_api_microversion

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_no_version(self):
        resp, resp_body = self.shares_client.send_microversion_request()

        self.assertEqual(self._MIN_API_VERSION,
                         resp[self.shares_client.API_MICROVERSIONS_HEADER])
        self.assertTrue(len(resp_body['versions']) > 0)
        self.assertNotIn('min_version', resp_body['versions'][0])
        self.assertNotIn('version', resp_body['versions'][0])

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_version_min_version(self):
        """Requests base version 1.0."""

        resp, resp_body = self.shares_client.send_microversion_request(
            self._MIN_API_VERSION)

        self.assertEqual(self._MIN_API_VERSION,
                         resp[self.shares_client.API_MICROVERSIONS_HEADER])
        self.assertTrue(len(resp_body['versions']) > 0)
        self.assertNotIn('min_version', resp_body['versions'][0])
        self.assertNotIn('version', resp_body['versions'][0])

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_version_max_configured_version(self):
        """Requests maximum API microversion.

        Requests the current maximum API microversion from the Manila API
        service, and confirms that version is the same as what Tempest is
        configured to request in other versioned API calls.
        """

        resp, resp_body = self.shares_client.send_microversion_request(
            self._MAX_API_VERSION)

        self.assertEqual(self._MAX_API_VERSION,
                         resp[self.shares_client.API_MICROVERSIONS_HEADER])
        self.assertTrue(len(resp_body['versions']) > 0)
        self.assertEqual(self._MAX_API_VERSION,
                         resp_body['versions'][0]['version'])

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_version_1_1(self):
        """Requests version 1.1, the first Manila microversion."""

        resp, resp_body = self.shares_client.send_microversion_request('1.1')

        self.assertEqual('1.1',
                         resp[self.shares_client.API_MICROVERSIONS_HEADER])
        self.assertTrue(len(resp_body['versions']) > 0)
        self.assertEqual(self._MIN_API_VERSION,
                         resp_body['versions'][0]['min_version'])

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_unavailable_versions(self):
        """Requests a version greater than the latest available version."""

        resp, resp_body = self.shares_client.send_microversion_request('1.1')
        self.assertTrue(len(resp_body['versions']) > 0)
        major_ver, minor_ver = [int(ver) for ver in
                                resp_body['versions'][0]['version'].split(".")]
        req_version = ('%s.%s' % (major_ver + 1, minor_ver + 1))
        resp, _ = self.shares_client.send_microversion_request(req_version)

        self.assertEqual(406, resp.status)

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_invalid_versions(self):
        """Requests invalid versions."""

        resp, resp_body = self.shares_client.send_microversion_request('1.2.1')

        self.assertEqual(400, resp.status)

        resp, _ = self.shares_client.send_microversion_request('None')

        self.assertEqual(400, resp.status)
