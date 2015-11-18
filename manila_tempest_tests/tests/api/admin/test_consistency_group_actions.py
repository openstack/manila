# Copyright 2015 Andrew Kerr
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
from tempest_lib.common.utils import data_utils
import testtools

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@testtools.skipUnless(CONF.share.run_consistency_group_tests,
                      'Consistency Group tests disabled.')
class ConsistencyGroupActionsTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ConsistencyGroupActionsTest, cls).resource_setup()
        # Create 2 share_types
        name = data_utils.rand_name("tempest-manila")
        extra_specs = cls.add_required_extra_specs_to_dict()
        share_type = cls.create_share_type(name, extra_specs=extra_specs)
        cls.share_type = share_type['share_type']

        name = data_utils.rand_name("tempest-manila")
        share_type = cls.create_share_type(name, extra_specs=extra_specs)
        cls.share_type2 = share_type['share_type']

        # Create a consistency group
        cls.consistency_group = cls.create_consistency_group(
            share_type_ids=[cls.share_type['id'], cls.share_type2['id']])

    @test.attr(type=["gate", ])
    def test_create_cg_from_cgsnapshot_with_multiple_share_types_v2_4(self):
        # Create cgsnapshot
        cgsnapshot = self.create_cgsnapshot_wait_for_active(
            self.consistency_group["id"],
            cleanup_in_class=False,
            version='2.4',
        )

        new_consistency_group = self.create_consistency_group(
            cleanup_in_class=False,
            source_cgsnapshot_id=cgsnapshot['id'],
            version='2.4',
        )

        # Verify share_types are the same
        expected_types = sorted(self.consistency_group['share_types'])
        actual_types = sorted(new_consistency_group['share_types'])
        self.assertEqual(expected_types, actual_types,
                         'Expected share types of %s, but got %s.' % (
                             expected_types, actual_types))

    @test.attr(type=["gate", ])
    def test_create_cg_from_multi_typed_populated_cgsnapshot_v2_4(self):
        share_name = data_utils.rand_name("tempest-share-name")
        share_desc = data_utils.rand_name("tempest-share-description")

        shares = self.create_shares([
            {'kwargs': {
                'cleanup_in_class': False,
                'name': share_name,
                'description': share_desc,
                'consistency_group_id': self.consistency_group['id'],
                'share_type_id': st_id,
            }} for st_id in (self.share_type['id'], self.share_type2['id'])
        ])

        cg_shares = self.shares_v2_client.list_shares(
            detailed=True,
            params={'consistency_group_id': self.consistency_group['id']},
            version='2.4',
        )

        cg_share_ids = [s['id'] for s in cg_shares]
        for share_id in (shares[0]['id'], shares[1]['id']):
            self.assertIn(share_id, cg_share_ids, 'Share %s not in '
                                                  'consistency group %s.' %
                          (share_id, self.consistency_group['id']))

        cgsnap_name = data_utils.rand_name("tempest-cgsnap-name")
        cgsnap_desc = data_utils.rand_name("tempest-cgsnap-description")
        cgsnapshot = self.create_cgsnapshot_wait_for_active(
            self.consistency_group["id"],
            name=cgsnap_name,
            description=cgsnap_desc,
            cleanup_in_class=False,
            version='2.4',
        )

        self.create_consistency_group(cleanup_in_class=False,
                                      source_cgsnapshot_id=cgsnapshot['id'],
                                      version='2.4')

        # TODO(akerr): Skip until bug 1483886 is resolved
        # Verify that the new shares correspond to correct share types
        # expected_share_types = [self.share_type['id'], self.share_type2[
        # 'id']]
        # actual_share_types = [s['share_type'] for s in new_cg_shares]
        # self.assertEqual(sorted(expected_share_types),
        #                  sorted(actual_share_types),
        #                  'Expected shares of types %s, got %s.' % (
        #                      sorted(expected_share_types),
        #                     sorted(actual_share_types)))
