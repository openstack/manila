# Copyright (c) 2015 Mirantis inc.
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

import ddt
import mock

from manila.api.v2 import availability_zones
from manila import context
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes


@ddt.ddt
class AvailabilityZonesAPITest(test.TestCase):

    @ddt.data(
        availability_zones.AvailabilityZoneControllerLegacy,
        availability_zones.AvailabilityZoneController,
    )
    def test_instantiate_controller(self, controller):
        az_controller = controller()

        self.assertTrue(hasattr(az_controller, "resource_name"))
        self.assertEqual("availability_zone", az_controller.resource_name)
        self.assertTrue(hasattr(az_controller, "_view_builder"))
        self.assertTrue(hasattr(az_controller._view_builder, "detail_list"))

    @ddt.data(
        ('1.0', availability_zones.AvailabilityZoneControllerLegacy),
        ('2.0', availability_zones.AvailabilityZoneControllerLegacy),
        ('2.6', availability_zones.AvailabilityZoneControllerLegacy),
        ('2.7', availability_zones.AvailabilityZoneController),
    )
    @ddt.unpack
    def test_index(self, version, controller):
        azs = [
            {
                "id": "fake_id1",
                "name": "fake_name1",
                "created_at": "fake_created_at",
                "updated_at": "fake_updated_at",
            },
            {
                "id": "fake_id2",
                "name": "fake_name2",
                "created_at": "fake_created_at",
                "updated_at": "fake_updated_at",
                "deleted": "False",
                "redundant_key": "redundant_value",
            },
        ]
        mock_policy_check = self.mock_object(policy, 'check_policy')
        self.mock_object(availability_zones.db, 'availability_zone_get_all',
                         mock.Mock(return_value=azs))
        az_controller = controller()
        ctxt = context.RequestContext("admin", "fake", True)
        req = fakes.HTTPRequest.blank('/shares', version=version)
        req.environ['manila.context'] = ctxt

        result = az_controller.index(req)

        (availability_zones.db.availability_zone_get_all.
            assert_called_once_with(ctxt))
        mock_policy_check.assert_called_once_with(
            ctxt, controller.resource_name, 'index')
        self.assertIsInstance(result, dict)
        self.assertEqual(["availability_zones"], list(result.keys()))
        self.assertIsInstance(result["availability_zones"], list)
        self.assertEqual(2, len(result["availability_zones"]))
        self.assertIn(azs[0], result["availability_zones"])
        azs[1].pop("deleted")
        azs[1].pop("redundant_key")
        self.assertIn(azs[1], result["availability_zones"])

    @ddt.data(
        ('1.0', availability_zones.AvailabilityZoneController),
        ('2.0', availability_zones.AvailabilityZoneController),
        ('2.6', availability_zones.AvailabilityZoneController),
        ('2.7', availability_zones.AvailabilityZoneControllerLegacy),
    )
    @ddt.unpack
    def test_index_with_unsupported_versions(self, version, controller):
        ctxt = context.RequestContext("admin", "fake", True)
        req = fakes.HTTPRequest.blank('/shares', version=version)
        req.environ['manila.context'] = ctxt
        az_controller = controller()

        self.assertRaises(
            exception.VersionNotFoundForAPIMethod, az_controller.index, req)
