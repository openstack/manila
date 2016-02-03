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
from tempest import test  # noqa

from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


class MigrationNFSTest(base.BaseSharesAdminTest):
    """Tests Share Migration.

    Tests migration in multi-backend environment.
    """

    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(MigrationNFSTest, cls).resource_setup()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled" % cls.protocol
            raise cls.skipException(message)
        if not CONF.share.run_migration_tests:
            raise cls.skipException("Migration tests disabled. Skipping.")

    @test.attr(type=["gate", ])
    @base.skip_if_microversion_lt("2.5")
    def test_migration_empty_v2_5(self):

        share, dest_pool = self._setup_migration()

        old_exports = share['export_locations']

        share = self.migrate_share(share['id'], dest_pool, version='2.5')

        self._validate_migration_successful(dest_pool, share, old_exports,
                                            version='2.5')

    @test.attr(type=["gate", ])
    @base.skip_if_microversion_lt("2.15")
    def test_migration_completion_empty_v2_15(self):

        share, dest_pool = self._setup_migration()

        old_exports = self.shares_v2_client.list_share_export_locations(
            share['id'], version='2.15')
        self.assertNotEmpty(old_exports)
        old_exports = [x['path'] for x in old_exports
                       if x['is_admin_only'] is False]
        self.assertNotEmpty(old_exports)

        share = self.migrate_share(
            share['id'], dest_pool, version='2.15', notify=False,
            wait_for_status='data_copying_completed')

        self._validate_migration_successful(dest_pool, share,
                                            old_exports, '2.15', notify=False)

        share = self.migration_complete(share['id'], dest_pool, version='2.15')

        self._validate_migration_successful(dest_pool, share, old_exports,
                                            version='2.15')

    def _setup_migration(self):

        pools = self.shares_client.list_pools()['pools']

        if len(pools) < 2:
            raise self.skipException("At least two different pool entries "
                                     "are needed to run migration tests. "
                                     "Skipping.")

        share = self.create_share(self.protocol)
        share = self.shares_client.get_share(share['id'])

        self.shares_v2_client.create_access_rule(
            share['id'], access_to="50.50.50.50", access_level="rw")

        self.shares_v2_client.wait_for_share_status(
            share['id'], 'active', status_attr='access_rules_status')

        self.shares_v2_client.create_access_rule(
            share['id'], access_to="51.51.51.51", access_level="ro")

        self.shares_v2_client.wait_for_share_status(
            share['id'], 'active', status_attr='access_rules_status')

        dest_pool = next((x for x in pools if x['name'] != share['host']),
                         None)

        self.assertIsNotNone(dest_pool)
        self.assertIsNotNone(dest_pool.get('name'))

        dest_pool = dest_pool['name']

        return share, dest_pool

    def _validate_migration_successful(self, dest_pool, share,
                                       old_exports, version, notify=True):
        if utils.is_microversion_lt(version, '2.9'):
            new_exports = share['export_locations']
            self.assertNotEmpty(new_exports)
        else:
            new_exports = self.shares_v2_client.list_share_export_locations(
                share['id'], version='2.9')
            self.assertNotEmpty(new_exports)
            new_exports = [x['path'] for x in new_exports if
                           x['is_admin_only'] is False]
            self.assertNotEmpty(new_exports)

        # Share migrated
        if notify:
            self.assertEqual(dest_pool, share['host'])
            for export in old_exports:
                self.assertFalse(export in new_exports)
            self.assertEqual('migration_success', share['task_state'])
        # Share not migrated yet
        else:
            self.assertNotEqual(dest_pool, share['host'])
            for export in old_exports:
                self.assertTrue(export in new_exports)
            self.assertEqual('data_copying_completed', share['task_state'])
