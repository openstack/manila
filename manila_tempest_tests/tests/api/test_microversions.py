# Copyright 2015 Goutham Pacha Ravi
# Copyright 2015 Clinton Knight
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

from tempest import config
from tempest import test

from manila_tempest_tests.tests.api import base

CONF = config.CONF

API_MICROVERSIONS_HEADER_LOWER = 'x-openstack-manila-api-version'
API_MICROVERSIONS_HEADER = 'X-OpenStack-Manila-API-Version'
_MIN_API_VERSION = CONF.share.min_api_microversion
_MAX_API_VERSION = CONF.share.max_api_microversion


class MicroversionsTest(base.BaseSharesTest):
    """Request and validate REST API Microversions.

    Sends HTTP GET requests to the version API to validate microversions.
    """

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_root_version(self):

        resp, resp_body = self.shares_v2_client.send_microversion_request()

        self.assertEqual(300, resp.status)

        version_list = resp_body['versions']
        ids = [v['id'] for v in version_list]
        self.assertEqual({'v1.0', 'v2.0'}, set(ids))

        self.assertNotIn(API_MICROVERSIONS_HEADER_LOWER, resp)
        self.assertNotIn('vary', resp)

        v1 = [v for v in version_list if v['id'] == 'v1.0'][0]
        self.assertEqual('', v1.get('min_version'))
        self.assertEqual('', v1.get('version'))

        v2 = [v for v in version_list if v['id'] == 'v2.0'][0]
        self.assertEqual(_MIN_API_VERSION, v2.get('min_version'))
        self.assertEqual(_MAX_API_VERSION, v2.get('version'))

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_v1_no_version(self):

        resp, resp_body = self.shares_v2_client.send_microversion_request(
            script_name='v1')

        self.assertEqual(200, resp.status)

        version_list = resp_body['versions']
        ids = [v['id'] for v in version_list]
        self.assertEqual({'v1.0'}, set(ids))

        self.assertEqual('1.0', resp.get(API_MICROVERSIONS_HEADER_LOWER))
        self.assertEqual(API_MICROVERSIONS_HEADER, resp.get('vary'))
        self.assertEqual('', version_list[0].get('min_version'))
        self.assertEqual('', version_list[0].get('version'))

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_v1_with_version(self):

        resp, resp_body = self.shares_v2_client.send_microversion_request(
            script_name='v1', version='5.0')

        self.assertEqual(200, resp.status)

        version_list = resp_body['versions']
        ids = [v['id'] for v in version_list]
        self.assertEqual({'v1.0'}, set(ids))

        self.assertEqual('1.0', resp.get(API_MICROVERSIONS_HEADER_LOWER))
        self.assertEqual(API_MICROVERSIONS_HEADER, resp.get('vary'))
        self.assertEqual('', version_list[0].get('min_version'))
        self.assertEqual('', version_list[0].get('version'))

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_v2_no_version(self):

        resp, resp_body = self.shares_v2_client.send_microversion_request(
            script_name='v2')

        self.assertEqual(200, resp.status)

        version_list = resp_body['versions']
        ids = [v['id'] for v in version_list]
        self.assertEqual({'v2.0'}, set(ids))

        self.assertEqual(_MIN_API_VERSION,
                         resp.get(API_MICROVERSIONS_HEADER_LOWER))
        self.assertEqual(API_MICROVERSIONS_HEADER, resp.get('vary'))
        self.assertEqual(_MIN_API_VERSION, version_list[0].get('min_version'))
        self.assertEqual(_MAX_API_VERSION, version_list[0].get('version'))

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_v2_min_version(self):

        resp, resp_body = self.shares_v2_client.send_microversion_request(
            script_name='v2', version=_MIN_API_VERSION)

        self.assertEqual(200, resp.status)

        version_list = resp_body['versions']
        ids = [v['id'] for v in version_list]
        self.assertEqual({'v2.0'}, set(ids))

        self.assertEqual(_MIN_API_VERSION,
                         resp.get(API_MICROVERSIONS_HEADER_LOWER))
        self.assertEqual(API_MICROVERSIONS_HEADER, resp.get('vary'))
        self.assertEqual(_MIN_API_VERSION, version_list[0].get('min_version'))
        self.assertEqual(_MAX_API_VERSION, version_list[0].get('version'))

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_v2_max_version(self):

        resp, resp_body = self.shares_v2_client.send_microversion_request(
            script_name='v2', version=_MAX_API_VERSION)

        self.assertEqual(200, resp.status)

        version_list = resp_body['versions']
        ids = [v['id'] for v in version_list]
        self.assertEqual({'v2.0'}, set(ids))

        self.assertEqual(_MAX_API_VERSION,
                         resp.get(API_MICROVERSIONS_HEADER_LOWER))
        self.assertEqual(API_MICROVERSIONS_HEADER, resp.get('vary'))
        self.assertEqual(_MIN_API_VERSION, version_list[0].get('min_version'))
        self.assertEqual(_MAX_API_VERSION, version_list[0].get('version'))

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_v2_invalid_version(self):

        resp, _ = self.shares_v2_client.send_microversion_request(
            script_name='v2', version='1.2.1')

        self.assertEqual(400, resp.status)

    @test.attr(type=["gate", "smoke", ])
    def test_microversions_v2_unacceptable_version(self):

        # First get max version from the server
        resp, resp_body = self.shares_v2_client.send_microversion_request(
            script_name='v2')

        self.assertEqual(200, resp.status)

        version_list = resp_body['versions']
        latest_version = version_list[0].get('version')
        major, minor = [int(ver) for ver in latest_version.split(".")]
        next_version = ('%s.%s' % (major + 1, minor + 1))

        # Request a version that is too high
        resp, _ = self.shares_v2_client.send_microversion_request(
            script_name='v2', version=next_version)

        self.assertEqual(406, resp.status)
