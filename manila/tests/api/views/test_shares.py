# Copyright (c) 2015 Mirantis, Inc.
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

from manila.api.views import shares
from manila import test
from manila.tests.api import fakes


class ViewBuilderTestCase(test.TestCase):

    def setUp(self):
        super(ViewBuilderTestCase, self).setUp()
        self.builder = shares.ViewBuilder()
        self.req = fakes.HTTPRequest.blank('/shares', version="2.6")

    def test__collection_name(self):
        self.assertEqual('shares', self.builder._collection_name)

    def test_detail_v_2_6(self):
        fake_share = {
            'id': 'fake_id',
            'share_type_id': 'fake_share_type_id',
            'share_type': {'name': 'fake_share_type_name'}
        }

        actual_result = self.builder.detail(self.req, fake_share)

        self.assertSubDictMatch(
            {
                'id': fake_share['id'],
                'share_type': fake_share['share_type_id'],
                'share_type_name': fake_share['share_type']['name'],
            },
            actual_result['share']
        )
