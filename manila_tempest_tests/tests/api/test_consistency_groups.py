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

from tempest import config  # noqa
from tempest.lib import exceptions as lib_exc  # noqa
from tempest import test  # noqa
import testtools  # noqa

from manila_tempest_tests.tests.api import base

CONF = config.CONF
CG_REQUIRED_ELEMENTS = {"id", "name", "description", "created_at", "status",
                        "share_types", "project_id", "host", "links"}
CGSNAPSHOT_REQUIRED_ELEMENTS = {"id", "name", "description", "created_at",
                                "status", "project_id", "links"}


@testtools.skipUnless(CONF.share.run_consistency_group_tests,
                      'Consistency Group tests disabled.')
class ConsistencyGroupsTest(base.BaseSharesTest):
    """Covers consistency group functionality."""

    @test.attr(type=["gate", ])
    def test_create_populate_delete_consistency_group_v2_4(self):
        # Create a consistency group
        consistency_group = self.create_consistency_group(
            cleanup_in_class=False, version='2.4')
        self.assertTrue(CG_REQUIRED_ELEMENTS.issubset(
            consistency_group.keys()),
            'At least one expected element missing from consistency group '
            'response. Expected %(expected)s, got %(actual)s.' % {
                "expected": CG_REQUIRED_ELEMENTS,
                "actual": consistency_group.keys()})
        # Populate
        share = self.create_share(consistency_group_id=consistency_group['id'],
                                  cleanup_in_class=False,
                                  client=self.shares_v2_client,
                                  version='2.4')
        # Delete
        params = {"consistency_group_id": consistency_group['id']}
        self.shares_v2_client.delete_share(share['id'], params=params,
                                           version='2.4')
        self.shares_client.wait_for_resource_deletion(share_id=share['id'])
        self.shares_v2_client.delete_consistency_group(consistency_group['id'],
                                                       version='2.4')
        self.shares_v2_client.wait_for_resource_deletion(
            cg_id=consistency_group['id'])

        # Verify
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_consistency_group,
                          consistency_group['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share,
                          share['id'])

    @test.attr(type=["gate", ])
    def test_create_delete_empty_cgsnapshot_v2_4(self):
        # Create base consistency group
        consistency_group = self.create_consistency_group(
            cleanup_in_class=False, version='2.4')
        # Create cgsnapshot
        cgsnapshot = self.create_cgsnapshot_wait_for_active(
            consistency_group["id"], cleanup_in_class=False, version='2.4')

        self.assertTrue(CGSNAPSHOT_REQUIRED_ELEMENTS.issubset(
            cgsnapshot.keys()),
            'At least one expected element missing from cgsnapshot response. '
            'Expected %(expected)s, got %(actual)s.' % {
                "expected": CGSNAPSHOT_REQUIRED_ELEMENTS,
                "actual": cgsnapshot.keys()})

        cgsnapshot_members = self.shares_v2_client.list_cgsnapshot_members(
            cgsnapshot['id'], version='2.4')

        self.assertEmpty(cgsnapshot_members,
                         'Expected 0 cgsnapshot members, got %s' % len(
                             cgsnapshot_members))

        # delete snapshot
        self.shares_v2_client.delete_cgsnapshot(cgsnapshot["id"],
                                                version='2.4')
        self.shares_v2_client.wait_for_resource_deletion(
            cgsnapshot_id=cgsnapshot["id"])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_cgsnapshot,
                          cgsnapshot['id'],
                          version='2.4')

    @test.attr(type=["gate", "smoke", ])
    def test_create_consistency_group_from_empty_cgsnapshot(self):
        # Create base consistency group
        consistency_group = self.create_consistency_group(
            cleanup_in_class=False)

        # Create cgsnapshot
        cgsnapshot = self.create_cgsnapshot_wait_for_active(
            consistency_group["id"], cleanup_in_class=False)

        cgsnapshot_members = self.shares_v2_client.list_cgsnapshot_members(
            cgsnapshot['id'])

        self.assertEmpty(cgsnapshot_members,
                         'Expected 0 cgsnapshot members, got %s' % len(
                             cgsnapshot_members))

        new_consistency_group = self.create_consistency_group(
            cleanup_in_class=False, source_cgsnapshot_id=cgsnapshot['id'])

        new_shares = self.shares_client.list_shares(
            params={'consistency_group_id': new_consistency_group['id']})

        self.assertEmpty(new_shares,
                         'Expected 0 new shares, got %s' % len(new_shares))

        msg = 'Expected cgsnapshot_id %s as source of share %s' % (
            cgsnapshot['id'], new_consistency_group['source_cgsnapshot_id'])
        self.assertEqual(new_consistency_group['source_cgsnapshot_id'],
                         cgsnapshot['id'], msg)

        msg = ('Unexpected share_types on new consistency group. Expected '
               '%s, got %s.' % (consistency_group['share_types'],
                                new_consistency_group['share_types']))
        self.assertEqual(sorted(consistency_group['share_types']),
                         sorted(new_consistency_group['share_types']), msg)
