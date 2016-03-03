# -*- coding: utf-8 -*-
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
from tempest.lib.common.utils import data_utils
from tempest import test
import testtools

from manila_tempest_tests.tests.api import base

CONF = config.CONF

CG_SIMPLE_KEYS = {"id", "name", "links"}
CG_DETAIL_REQUIRED_KEYS = {"id", "name", "description", "created_at", "status",
                           "project_id", "host", "links"}
CGSNAPSHOT_SIMPLE_KEYS = {"id", "name", "links"}
CGSNAPSHOT_DETAIL_REQUIRED_KEYS = {"id", "name", "description", "created_at",
                                   "status", "project_id", "links"}


@testtools.skipUnless(CONF.share.run_consistency_group_tests,
                      'Consistency Group tests disabled.')
class ConsistencyGroupActionsTest(base.BaseSharesTest):
    """Covers consistency group functionality."""

    @classmethod
    def resource_setup(cls):
        super(ConsistencyGroupActionsTest, cls).resource_setup()

        # Create first consistency group
        cls.cg_name = data_utils.rand_name("tempest-cg-name")
        cls.cg_desc = data_utils.rand_name("tempest-cg-description")
        cls.cg = cls.create_consistency_group(
            name=cls.cg_name, description=cls.cg_desc)

        # Create second consistency group for purposes of sorting and snapshot
        # filtering
        cls.cg2 = cls.create_consistency_group(
            name=cls.cg_name, description=cls.cg_desc)

        # Create 2 shares inside first CG and 1 inside second CG
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        cls.share_size = 1
        cls.share_size2 = 2
        cls.shares = cls.create_shares([
            {'kwargs': {
                'name': cls.share_name,
                'description': cls.share_desc,
                'size': size,
                'consistency_group_id': cg_id,
            }} for size, cg_id in ((cls.share_size, cls.cg['id']),
                                   (cls.share_size2, cls.cg['id']),
                                   (cls.share_size, cls.cg2['id']))
        ])

        # Create CG snapshots
        cls.cgsnap_name = data_utils.rand_name("tempest-cgsnap-name")
        cls.cgsnap_desc = data_utils.rand_name("tempest-cgsnap-description")

        cls.cgsnapshot = cls.create_cgsnapshot_wait_for_active(
            cls.cg["id"],
            name=cls.cgsnap_name,
            description=cls.cgsnap_desc)

        cls.cgsnapshot2 = cls.create_cgsnapshot_wait_for_active(
            cls.cg2['id'], name=cls.cgsnap_name, description=cls.cgsnap_desc)

    @test.attr(type=["gate", ])
    def test_get_consistency_group_v2_4(self):

        # Get consistency group
        consistency_group = self.shares_v2_client.get_consistency_group(
            self.cg['id'], version='2.4')

        # Verify keys
        actual_keys = set(consistency_group.keys())
        self.assertTrue(CG_DETAIL_REQUIRED_KEYS.issubset(actual_keys),
                        'Not all required keys returned for consistency '
                        'group %s.  Expected at least: %s, found %s' % (
                            consistency_group['id'],
                            CG_DETAIL_REQUIRED_KEYS,
                            actual_keys))

        # Verify values
        msg = "Expected name: '%s', actual name: '%s'" % (
            self.cg_name, consistency_group["name"])
        self.assertEqual(self.cg_name, str(consistency_group["name"]), msg)

        msg = "Expected description: '%s', actual description: '%s'" % (
            self.cg_desc, consistency_group["description"])
        self.assertEqual(self.cg_desc, str(consistency_group["description"]),
                         msg)

    @test.attr(type=["gate", ])
    def test_get_share_v2_4(self):

        # Get share
        share = self.shares_v2_client.get_share(self.shares[0]['id'],
                                                version='2.4')

        # Verify keys
        expected_keys = {"status", "description", "links", "availability_zone",
                         "created_at", "export_location", "share_proto",
                         "name", "snapshot_id", "id", "size",
                         "consistency_group_id"}
        actual_keys = set(share.keys())
        self.assertTrue(expected_keys.issubset(actual_keys),
                        'Not all required keys returned for share %s.  '
                        'Expected at least: %s, found %s' % (share['id'],
                                                             expected_keys,
                                                             actual_keys))

        # Verify values
        msg = "Expected name: '%s', actual name: '%s'" % (self.share_name,
                                                          share["name"])
        self.assertEqual(self.share_name, str(share["name"]), msg)

        msg = "Expected description: '%s', actual description: '%s'" % (
            self.share_desc, share["description"])
        self.assertEqual(self.share_desc, str(share["description"]), msg)

        msg = "Expected size: '%s', actual size: '%s'" % (self.share_size,
                                                          share["size"])
        self.assertEqual(self.share_size, int(share["size"]), msg)

        msg = "Expected consistency_group_id: '%s', actual value: '%s'" % (
            self.cg["id"], share["consistency_group_id"])
        self.assertEqual(self.cg["id"], share["consistency_group_id"], msg)

    @test.attr(type=["gate", ])
    def test_list_consistency_groups_v2_4(self):

        # List consistency groups
        consistency_groups = self.shares_v2_client.list_consistency_groups(
            version='2.4')

        # Verify keys
        [self.assertEqual(CG_SIMPLE_KEYS, set(cg.keys())) for cg in
         consistency_groups]

        # Consistency group ids are in list exactly once
        for cg_id in (self.cg["id"], self.cg2["id"]):
            gen = [cgid["id"] for cgid in consistency_groups
                   if cgid["id"] == cg_id]
            msg = ("Expected id %s exactly once in consistency group list" %
                   cg_id)
            self.assertEqual(1, len(gen), msg)

    @test.attr(type=["gate", ])
    def test_list_consistency_groups_with_detail_v2_4(self):

        # List consistency groups
        consistency_groups = self.shares_v2_client.list_consistency_groups(
            detailed=True, version='2.4')

        # Verify keys
        [self.assertTrue(CG_DETAIL_REQUIRED_KEYS.issubset(set(cg.keys())))
         for cg in consistency_groups]

        # Consistency group ids are in list exactly once
        for cg_id in (self.cg["id"], self.cg2["id"]):
            gen = [cgid["id"] for cgid in consistency_groups
                   if cgid["id"] == cg_id]
            msg = ("Expected id %s exactly once in consistency group list" %
                   cg_id)
            self.assertEqual(1, len(gen), msg)

    @test.attr(type=["gate", ])
    def test_filter_shares_by_consistency_group_id_v2_4(self):

        shares = self.shares_v2_client.list_shares(
            detailed=True,
            params={'consistency_group_id': self.cg['id']},
            version='2.4'
        )

        share_ids = [share['id'] for share in shares]

        self.assertEqual(2, len(shares),
                         'Incorrect number of shares returned. Expected 2, '
                         'got %s' % len(shares))
        self.assertIn(self.shares[0]['id'], share_ids,
                      'Share %s expected in returned list, but got %s'
                      % (self.shares[0]['id'], share_ids))
        self.assertIn(self.shares[1]['id'], share_ids,
                      'Share %s expected in returned list, but got %s'
                      % (self.shares[0]['id'], share_ids))

    @test.attr(type=["gate", ])
    def test_get_cgsnapshot_v2_4(self):

        # Get consistency group
        consistency_group = self.shares_v2_client.get_consistency_group(
            self.cg['id'], version='2.4')

        # Verify keys
        actual_keys = set(consistency_group.keys())
        self.assertTrue(CG_DETAIL_REQUIRED_KEYS.issubset(actual_keys),
                        'Not all required keys returned for consistency '
                        'group %s.  Expected at least: %s, found %s' % (
                            consistency_group['id'],
                            CG_DETAIL_REQUIRED_KEYS,
                            actual_keys))

        # Verify values
        msg = "Expected name: '%s', actual name: '%s'" % (
            self.cg_name, consistency_group["name"])
        self.assertEqual(self.cg_name, str(consistency_group["name"]), msg)

        msg = "Expected description: '%s', actual description: '%s'" % (
            self.cg_desc, consistency_group["description"])
        self.assertEqual(self.cg_desc, str(consistency_group["description"]),
                         msg)

    @test.attr(type=["gate", ])
    def test_get_cgsnapshot_members_v2_4(self):

        cgsnapshot_members = self.shares_v2_client.list_cgsnapshot_members(
            self.cgsnapshot['id'], version='2.4')
        member_share_ids = [member['share_id'] for member in
                            cgsnapshot_members]
        self.assertEqual(2, len(cgsnapshot_members),
                         'Unexpected number of cgsnapshot members. Expected '
                         '2, got %s.' % len(cgsnapshot_members))
        # Verify each share is represented in the cgsnapshot appropriately
        for share_id in (self.shares[0]['id'], self.shares[1]['id']):
            self.assertIn(share_id, member_share_ids,
                          'Share missing %s missing from cgsnapshot. Found %s.'
                          % (share_id, member_share_ids))
        for share in (self.shares[0], self.shares[1]):
            for member in cgsnapshot_members:
                if share['id'] == member['share_id']:
                    self.assertEqual(share['size'], member['size'])
                    self.assertEqual(share['share_proto'],
                                     member['share_protocol'])
                    # TODO(akerr): Add back assert when bug 1483886 is fixed
                    # self.assertEqual(share['share_type'],
                    #                  member['share_type_id'])

    @test.attr(type=["gate", "smoke", ])
    def test_create_consistency_group_from_populated_cgsnapshot_v2_4(self):

        cgsnapshot_members = self.shares_v2_client.list_cgsnapshot_members(
            self.cgsnapshot['id'], version='2.4')

        new_consistency_group = self.create_consistency_group(
            cleanup_in_class=False,
            source_cgsnapshot_id=self.cgsnapshot['id'],
            version='2.4'
        )

        new_shares = self.shares_v2_client.list_shares(
            params={'consistency_group_id': new_consistency_group['id']},
            detailed=True,
            version='2.4'
        )

        # Verify each new share is available
        for share in new_shares:
            self.assertEqual('available', share['status'],
                             'Share %s is not in available status.'
                             % share['id'])

        # Verify each cgsnapshot member is represented in the new cg
        # appropriately
        share_source_member_ids = [share['source_cgsnapshot_member_id'] for
                                   share in new_shares]
        for member in cgsnapshot_members:
            self.assertIn(member['id'], share_source_member_ids,
                          'cgsnapshot member %s not represented by '
                          'consistency group %s.' % (
                              member['id'], new_consistency_group['id']))
            for share in new_shares:
                if share['source_cgsnapshot_member_id'] == member['id']:
                    self.assertEqual(member['size'], share['size'])
                    self.assertEqual(member['share_protocol'],
                                     share['share_proto'])
                    # TODO(akerr): Add back assert when bug 1483886 is fixed
                    # self.assertEqual(member['share_type_id'],
                    #                  share['share_type'])


@testtools.skipUnless(CONF.share.run_consistency_group_tests,
                      'Consistency Group tests disabled.')
class ConsistencyGroupRenameTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(ConsistencyGroupRenameTest, cls).resource_setup()

        # Create consistency group
        cls.cg_name = data_utils.rand_name("tempest-cg-name")
        cls.cg_desc = data_utils.rand_name("tempest-cg-description")
        cls.consistency_group = cls.create_consistency_group(
            name=cls.cg_name,
            description=cls.cg_desc,
        )

    @test.attr(type=["gate", ])
    def test_update_consistency_group_v2_4(self):

        # Get consistency_group
        consistency_group = self.shares_v2_client.get_consistency_group(
            self.consistency_group['id'], version='2.4')
        self.assertEqual(self.cg_name, consistency_group["name"])
        self.assertEqual(self.cg_desc, consistency_group["description"])

        # Update consistency_group
        new_name = data_utils.rand_name("tempest-new-name")
        new_desc = data_utils.rand_name("tempest-new-description")
        updated = self.shares_v2_client.update_consistency_group(
            consistency_group["id"],
            name=new_name,
            description=new_desc,
            version='2.4'
        )
        self.assertEqual(new_name, updated["name"])
        self.assertEqual(new_desc, updated["description"])

        # Get consistency_group
        consistency_group = self.shares_v2_client.get_consistency_group(
            self.consistency_group['id'], version='2.4')
        self.assertEqual(new_name, consistency_group["name"])
        self.assertEqual(new_desc, consistency_group["description"])

    @test.attr(type=["gate", ])
    def test_create_update_read_consistency_group_with_unicode_v2_4(self):
        value1 = u'ಠ_ಠ'
        value2 = u'ಠ_ರೃ'
        # Create consistency_group
        consistency_group = self.create_consistency_group(
            cleanup_in_class=False,
            name=value1,
            description=value1,
            version='2.4'
        )
        self.assertEqual(value1, consistency_group["name"])
        self.assertEqual(value1, consistency_group["description"])

        # Update consistency_group
        updated = self.shares_v2_client.update_consistency_group(
            consistency_group["id"],
            name=value2,
            description=value2,
            version='2.4'
        )
        self.assertEqual(value2, updated["name"])
        self.assertEqual(value2, updated["description"])

        # Get consistency_group
        consistency_group = self.shares_v2_client.get_consistency_group(
            consistency_group['id'], version='2.4')
        self.assertEqual(value2, consistency_group["name"])
        self.assertEqual(value2, consistency_group["description"])
