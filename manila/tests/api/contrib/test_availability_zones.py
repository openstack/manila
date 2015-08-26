# Copyright 2015 Mirantis Inc.
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

from manila.api.contrib import availability_zones
from manila import db
from manila import test
from manila.tests.api import fakes


class AvailabilityZonesApiTest(test.TestCase):
    def setUp(self):
        super(AvailabilityZonesApiTest, self).setUp()
        self.controller = availability_zones.Controller()

    def test_index(self):
        fake_az = [{'test': 'test'}]
        self.mock_object(db, 'availability_zone_get_all',
                         mock.Mock(return_value=fake_az))
        req = fakes.HTTPRequest.blank('/v2/fake/types/1')

        actual_result = self.controller.index(req)

        self.assertDictMatch({'availability_zones': fake_az}, actual_result)
        db.availability_zone_get_all.assert_called_once_with(mock.ANY)
