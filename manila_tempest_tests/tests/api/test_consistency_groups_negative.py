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
from tempest.lib import exceptions as lib_exc
from tempest import test
import testtools

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@testtools.skipUnless(CONF.share.run_consistency_group_tests,
                      'Consistency Group tests disabled.')
class ConsistencyGroupsNegativeTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(ConsistencyGroupsNegativeTest, cls).resource_setup()
        # Create a consistency group
        cls.cg_name = data_utils.rand_name("tempest-cg-name")
        cls.cg_desc = data_utils.rand_name("tempest-cg-description")
        cls.consistency_group = cls.create_consistency_group(
            name=cls.cg_name,
            description=cls.cg_desc
        )
        # Create a share in the consistency group
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        cls.share_size = 1
        cls.share = cls.create_share(
            name=cls.share_name,
            description=cls.share_desc,
            size=cls.share_size,
            consistency_group_id=cls.consistency_group['id'],
            client=cls.shares_v2_client
        )
        # Create a cgsnapshot of the consistency group
        cls.cgsnap_name = data_utils.rand_name("tempest-cgsnap-name")
        cls.cgsnap_desc = data_utils.rand_name("tempest-cgsnap-description")
        cls.cgsnapshot = cls.create_cgsnapshot_wait_for_active(
            cls.consistency_group["id"],
            name=cls.cgsnap_name,
            description=cls.cgsnap_desc)

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_create_cg_with_invalid_source_cgsnapshot_id_value_v2_4(
            self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_consistency_group,
                          source_cgsnapshot_id='foobar',
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_create_cg_with_nonexistent_source_cgsnapshot_id_value_v2_4(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_consistency_group,
                          source_cgsnapshot_id=self.share['id'],
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_create_cg_with_invalid_share_network_id_value_v2_4(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_consistency_group,
                          share_network_id='foobar',
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_create_cg_with_nonexistent_share_network_id_value_v2_4(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_consistency_group,
                          share_network_id=self.share['id'],
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_create_cg_with_invalid_share_type_id_value_v2_4(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_consistency_group,
                          share_type_ids=['foobar'],
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_create_cg_with_nonexistent_share_type_id_value_v2_4(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_consistency_group,
                          share_type_ids=[self.share['id']],
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_create_cgsnapshot_with_invalid_cg_id_value_v2_4(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_cgsnapshot_wait_for_active,
                          'foobar',
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_create_cgsnapshot_with_nonexistent_cg_id_value_v2_4(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.create_cgsnapshot_wait_for_active,
                          self.share['id'],
                          cleanup_in_class=False,
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_get_cg_with_wrong_id_v2_4(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_consistency_group,
                          "wrong_consistency_group_id",
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_get_cg_without_passing_cg_id_v2_4(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_consistency_group,
                          '',
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_update_cg_with_wrong_id_v2_4(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.update_consistency_group,
                          'wrong_consistency_group_id',
                          name='new_name',
                          description='new_description',
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_delete_cg_with_wrong_id_v2_4(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.delete_consistency_group,
                          "wrong_consistency_group_id",
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_delete_cg_without_passing_cg_id_v2_4(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.delete_consistency_group,
                          '',
                          version='2.4')

    @test.attr(type=["negative", "gate", ])
    def test_delete_cg_in_use_by_cgsnapshot_v2_4(self):
        # Attempt delete of share type
        self.assertRaises(lib_exc.Conflict,
                          self.shares_v2_client.delete_consistency_group,
                          self.consistency_group['id'],
                          version='2.4')

    @test.attr(type=["negative", "gate", ])
    def test_delete_share_in_use_by_cgsnapshot_v2_4(self):
        # Attempt delete of share type
        params = {'consistency_group_id': self.share['consistency_group_id']}
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_v2_client.delete_share,
                          self.share['id'],
                          params=params,
                          version='2.4')

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_delete_cg_containing_a_share_v2_4(self):
        self.assertRaises(lib_exc.Conflict,
                          self.shares_v2_client.delete_consistency_group,
                          self.consistency_group['id'],
                          version='2.4')
        # Verify consistency group is not put into error state from conflict
        cg = self.shares_v2_client.get_consistency_group(
            self.consistency_group['id'], version='2.4')
        self.assertEqual('available', cg['status'])

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_filter_shares_on_invalid_cg_id_v2_4(self):
        shares = self.shares_v2_client.list_shares(
            detailed=True,
            params={'consistency_group_id': 'foobar'},
            version='2.4'
        )

        self.assertEqual(0, len(shares),
                         'Incorrect number of shares returned. Expected 0, '
                         'got %s.' % len(shares))

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_filter_shares_on_nonexistent_cg_id_v2_4(self):
        shares = self.shares_v2_client.list_shares(
            detailed=True,
            params={'consistency_group_id': self.share['id']},
            version='2.4'
        )

        self.assertEqual(0, len(shares),
                         'Incorrect number of shares returned. Expected 0, '
                         'got %s.' % len(shares))

    @test.attr(type=["negative", "smoke", "gate", ])
    def test_filter_shares_on_empty_cg_id_v2_4(self):
        consistency_group = self.create_consistency_group(
            name='tempest_cg',
            description='tempest_cg_desc',
            cleanup_in_class=False,
            version='2.4',
        )
        shares = self.shares_v2_client.list_shares(
            detailed=True,
            params={'consistency_group_id': consistency_group['id']},
            version='2.4',
        )

        self.assertEqual(0, len(shares),
                         'Incorrect number of shares returned. Expected 0, '
                         'got %s.' % len(shares))
