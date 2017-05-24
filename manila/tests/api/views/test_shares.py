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

import ddt

from manila.api.views import shares
from manila import test
from manila.tests.api.contrib import stubs
from manila.tests.api import fakes


@ddt.ddt
class ViewBuilderTestCase(test.TestCase):

    def setUp(self):
        super(ViewBuilderTestCase, self).setUp()
        self.builder = shares.ViewBuilder()
        self.fake_share = self._get_fake_share()

    def _get_fake_share(self):

        fake_share = {
            'share_type_id': 'fake_share_type_id',
            'share_type': {
                'name': 'fake_share_type_name',
            },
            'export_location': 'fake_export_location',
            'export_locations': ['fake_export_location'],
            'access_rules_status': 'fake_rule_status',
            'instance': {
                'share_type': {
                    'name': 'fake_share_type_name',
                },
                'share_type_id': 'fake_share_type_id',
            },
            'replication_type': 'fake_replication_type',
            'has_replicas': False,
            'user_id': 'fake_userid',
            'snapshot_support': True,
            'create_share_from_snapshot_support': True,
            'revert_to_snapshot_support': True,
        }
        return stubs.stub_share('fake_id', **fake_share)

    def test__collection_name(self):
        self.assertEqual('shares', self.builder._collection_name)

    @ddt.data('2.6', '2.9', '2.10', '2.11', '2.16', '2.24', '2.27')
    def test_detail(self, microversion):
        req = fakes.HTTPRequest.blank('/shares', version=microversion)

        result = self.builder.detail(req, self.fake_share)

        expected = {
            'id': self.fake_share['id'],
            'share_type': self.fake_share['share_type_id'],
            'share_type_name': self.fake_share['share_type']['name'],
            'export_location': 'fake_export_location',
            'export_locations': ['fake_export_location'],
            'snapshot_support': True,
        }
        if self.is_microversion_ge(microversion, '2.9'):
            expected.pop('export_location')
            expected.pop('export_locations')
        if self.is_microversion_ge(microversion, '2.10'):
            expected['access_rules_status'] = 'fake_rule_status'
        if self.is_microversion_ge(microversion, '2.11'):
            expected['replication_type'] = 'fake_replication_type'
            expected['has_replicas'] = False
        if self.is_microversion_ge(microversion, '2.16'):
            expected['user_id'] = 'fake_userid'
        if self.is_microversion_ge(microversion, '2.24'):
            expected['create_share_from_snapshot_support'] = True
        if self.is_microversion_ge(microversion, '2.27'):
            expected['revert_to_snapshot_support'] = True

        self.assertSubDictMatch(expected, result['share'])
