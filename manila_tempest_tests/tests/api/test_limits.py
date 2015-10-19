# Copyright 2014 Mirantis Inc.
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

from tempest import test  # noqa

from manila_tempest_tests.tests.api import base


class ShareLimitsTest(base.BaseSharesTest):

    @test.attr(type=["gate", "smoke", ])
    def test_limits_keys(self):

        # list limits
        limits = self.shares_client.get_limits()

        # verify response
        keys = ["rate", "absolute"]
        [self.assertIn(key, limits.keys()) for key in keys]

        abs_keys = [
            "maxTotalShareGigabytes",
            "maxTotalShares",
            "maxTotalShareSnapshots",
            "maxTotalShareNetworks",
            "maxTotalSnapshotGigabytes",
            "totalSharesUsed",
            "totalShareSnapshotsUsed",
            "totalShareNetworksUsed",
            "totalShareGigabytesUsed",
            "totalSnapshotGigabytesUsed",
        ]
        [self.assertIn(key, limits["absolute"].keys()) for key in abs_keys]

    @test.attr(type=["gate", "smoke", ])
    def test_limits_values(self):

        # list limits
        limits = self.shares_client.get_limits()

        # verify integer values for absolute limits
        abs_l = limits["absolute"]
        self.assertGreater(int(abs_l["maxTotalShareGigabytes"]), -2)
        self.assertGreater(int(abs_l["maxTotalShares"]), -2)
        self.assertGreater(int(abs_l["maxTotalShareSnapshots"]), -2)
        self.assertGreater(int(abs_l["maxTotalShareNetworks"]), -2)
        self.assertGreater(int(abs_l["maxTotalSnapshotGigabytes"]), -2)
        self.assertGreater(int(abs_l["totalSharesUsed"]), -2)
        self.assertGreater(int(abs_l["totalShareSnapshotsUsed"]), -2)
        self.assertGreater(int(abs_l["totalShareNetworksUsed"]), -2)
        self.assertGreater(int(abs_l["totalShareGigabytesUsed"]), -2)
        self.assertGreater(int(abs_l["totalSnapshotGigabytesUsed"]), -2)
