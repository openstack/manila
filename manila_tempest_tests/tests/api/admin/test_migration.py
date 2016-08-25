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

from tempest import config
from tempest import test

from manila_tempest_tests.common import constants
from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


class MigrationNFSTest(base.BaseSharesAdminTest):
    """Tests Share Migration.

    Tests share migration in multi-backend environment.
    """

    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(MigrationNFSTest, cls).resource_setup()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled" % cls.protocol
            raise cls.skipException(message)
        if not CONF.share.run_migration_tests:
            raise cls.skipException("Share migration tests are disabled.")

    @test.attr(type=[base.TAG_POSITIVE, base.TAG_BACKEND])
    @base.skip_if_microversion_lt("2.15")
    def test_migration_cancel(self):

        share, dest_pool = self._setup_migration()

        old_exports = self.shares_v2_client.list_share_export_locations(
            share['id'], version='2.15')
        self.assertNotEmpty(old_exports)
        old_exports = [x['path'] for x in old_exports
                       if x['is_admin_only'] is False]
        self.assertNotEmpty(old_exports)

        task_states = (constants.TASK_STATE_DATA_COPYING_COMPLETED,
                       constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)

        share = self.migrate_share(
            share['id'], dest_pool, version='2.15', notify=False,
            wait_for_status=task_states)

        self._validate_migration_successful(
            dest_pool, share, task_states, '2.15', notify=False)

        share = self.migration_cancel(share['id'], dest_pool)

        self._validate_migration_successful(
            dest_pool, share, constants.TASK_STATE_MIGRATION_CANCELLED,
            '2.15', notify=False)

    @test.attr(type=[base.TAG_POSITIVE, base.TAG_BACKEND])
    @base.skip_if_microversion_lt("2.5")
    def test_migration_empty_v2_5(self):

        share, dest_pool = self._setup_migration()

        share = self.migrate_share(share['id'], dest_pool, version='2.5')

        self._validate_migration_successful(
            dest_pool, share, constants.TASK_STATE_MIGRATION_SUCCESS,
            version='2.5')

    @test.attr(type=[base.TAG_POSITIVE, base.TAG_BACKEND])
    @base.skip_if_microversion_lt("2.15")
    def test_migration_completion_empty_v2_15(self):

        share, dest_pool = self._setup_migration()

        old_exports = self.shares_v2_client.list_share_export_locations(
            share['id'], version='2.15')
        self.assertNotEmpty(old_exports)
        old_exports = [x['path'] for x in old_exports
                       if x['is_admin_only'] is False]
        self.assertNotEmpty(old_exports)

        task_states = (constants.TASK_STATE_DATA_COPYING_COMPLETED,
                       constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)

        share = self.migrate_share(
            share['id'], dest_pool, version='2.15', notify=False,
            wait_for_status=task_states)

        self._validate_migration_successful(
            dest_pool, share, task_states, '2.15', notify=False)

        share = self.migration_complete(share['id'], dest_pool, version='2.15')

        self._validate_migration_successful(
            dest_pool, share, constants.TASK_STATE_MIGRATION_SUCCESS,
            version='2.15')

    def _setup_migration(self):

        pools = self.shares_v2_client.list_pools(detail=True)['pools']

        if len(pools) < 2:
            raise self.skipException("At least two different pool entries are "
                                     "needed to run share migration tests.")

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

        default_type = self.shares_v2_client.list_share_types(
            default=True)['share_type']

        dest_pool = utils.choose_matching_backend(share, pools, default_type)

        self.assertIsNotNone(dest_pool)
        self.assertIsNotNone(dest_pool.get('name'))

        dest_pool = dest_pool['name']

        return share, dest_pool

    def _validate_migration_successful(self, dest_pool, share,
                                       status_to_wait, version, notify=True):

        statuses = ((status_to_wait,)
                    if not isinstance(status_to_wait, (tuple, list, set))
                    else status_to_wait)

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
        # Share not migrated yet
        else:
            self.assertNotEqual(dest_pool, share['host'])
        self.assertIn(share['task_state'], statuses)
