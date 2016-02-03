# Copyright 2015 Hitachi Data Systems.
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

from manila_tempest_tests.tests.api import base

CONF = config.CONF


class MigrationNFSTest(base.BaseSharesAdminTest):
    """Tests Share Migration.

    Tests migration in multi-backend environment.
    """

    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(MigrationNFSTest, cls).resource_setup()
        if not CONF.share.run_migration_tests:
            raise cls.skipException("Migration tests disabled. Skipping.")

        cls.share = cls.create_share(cls.protocol)
        cls.share = cls.shares_client.get_share(cls.share['id'])
        pools = cls.shares_client.list_pools()['pools']

        if len(pools) < 2:
            raise cls.skipException("At least two different pool entries "
                                    "are needed to run migration tests. "
                                    "Skipping.")
        cls.dest_pool = next((x for x in pools
                              if x['name'] != cls.share['host']), None)

    @test.attr(type=["gate", "negative", ])
    @base.skip_if_microversion_lt("2.15")
    def test_migration_cancel_invalid(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migration_cancel,
            self.share['id'])

    @test.attr(type=["gate", "negative", ])
    @base.skip_if_microversion_lt("2.15")
    def test_migration_get_progress_invalid(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migration_get_progress,
            self.share['id'])

    @test.attr(type=["gate", "negative", ])
    @base.skip_if_microversion_lt("2.15")
    def test_migration_complete_invalid(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migration_complete,
            self.share['id'])

    @test.attr(type=["gate", "negative", ])
    @base.skip_if_microversion_lt("2.5")
    def test_migrate_share_with_snapshot_v2_5(self):
        snap = self.create_snapshot_wait_for_active(self.share['id'])
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool, True, version='2.5')
        self.shares_client.delete_snapshot(snap['id'])
        self.shares_client.wait_for_resource_deletion(snapshot_id=snap["id"])

    @test.attr(type=["gate", "negative", ])
    @base.skip_if_microversion_lt("2.5")
    def test_migrate_share_same_host_v2_5(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.share['host'], True, version='2.5')

    @test.attr(type=["gate", "negative", ])
    @base.skip_if_microversion_lt("2.5")
    def test_migrate_share_not_available_v2_5(self):
        self.shares_client.reset_state(self.share['id'], 'error')
        self.shares_client.wait_for_share_status(self.share['id'], 'error')
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool, True, version='2.5')
        self.shares_client.reset_state(self.share['id'], 'available')
        self.shares_client.wait_for_share_status(self.share['id'], 'available')
