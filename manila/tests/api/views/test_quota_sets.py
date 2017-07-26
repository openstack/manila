# Copyright (c) 2017 Mirantis, Inc.
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

import ddt

from manila.api.openstack import api_version_request as api_version
from manila.api.views import quota_sets
from manila import test
from manila.tests.api import fakes


@ddt.ddt
class ViewBuilderTestCase(test.TestCase):

    def setUp(self):
        super(ViewBuilderTestCase, self).setUp()
        self.builder = quota_sets.ViewBuilder()

    def test__collection_name(self):
        self.assertEqual('quota_set', self.builder._collection_name)

    @ddt.data(
        ('fake_project_id', 'fake_share_type_id', "2.40"),
        (None, 'fake_share_type_id', "2.40"),
        ('fake_project_id', None, "2.40"),
        (None, None, "2.40"),
        ('fake_project_id', 'fake_share_type_id', "2.39"),
        (None, 'fake_share_type_id', "2.39"),
        ('fake_project_id', None, "2.39"),
        (None, None, "2.39"),
    )
    @ddt.unpack
    def test_detail_list_with_share_type(self, project_id, share_type,
                                         microversion):
        req = fakes.HTTPRequest.blank('/quota-sets', version=microversion)
        quota_set = {
            "shares": 13,
            "gigabytes": 31,
            "snapshots": 14,
            "snapshot_gigabytes": 41,
            "share_groups": 15,
            "share_group_snapshots": 51,
            "share_networks": 16,
        }
        expected = {self.builder._collection_name: {
            "shares": quota_set["shares"],
            "gigabytes": quota_set["gigabytes"],
            "snapshots": quota_set["snapshots"],
            "snapshot_gigabytes": quota_set["snapshot_gigabytes"],
        }}
        if project_id:
            expected[self.builder._collection_name]['id'] = project_id
        if not share_type:
            expected[self.builder._collection_name][
                "share_networks"] = quota_set["share_networks"]
            if (api_version.APIVersionRequest(microversion) >= (
                    api_version.APIVersionRequest("2.40"))):
                expected[self.builder._collection_name][
                    "share_groups"] = quota_set["share_groups"]
                expected[self.builder._collection_name][
                    "share_group_snapshots"] = quota_set[
                        "share_group_snapshots"]

        result = self.builder.detail_list(
            req, quota_set, project_id=project_id, share_type=share_type)

        self.assertEqual(expected, result)
