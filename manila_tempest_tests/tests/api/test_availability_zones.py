# Copyright 2015 mirantis Inc.
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

from tempest import test

from manila_tempest_tests.tests.api import base


class AvailabilityZonesTest(base.BaseSharesTest):

    def _list_availability_zones_assertions(self, availability_zones):
        self.assertTrue(len(availability_zones) > 0)
        keys = ("created_at", "updated_at", "name", "id")
        for az in availability_zones:
            for key in keys:
                self.assertIn(key, az)

    @test.attr(type=["smoke", "gate"])
    def test_list_availability_zones_extension(self):
        azs = self.shares_client.list_availability_zones()
        self._list_availability_zones_assertions(azs)
