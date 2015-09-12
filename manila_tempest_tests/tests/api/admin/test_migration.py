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
    def test_migration_empty_v2_5(self):

        pools = self.shares_client.list_pools()['pools']

        if len(pools) < 2:
            raise self.skipException("At least two different pool entries "
                                     "are needed to run migration tests. "
                                     "Skipping.")

        share = self.create_share(self.protocol)
        share = self.shares_client.get_share(share['id'])

        dest_pool = next((x for x in pools if x['name'] != share['host']),
                         None)

        self.assertIsNotNone(dest_pool)
        self.assertIsNotNone(dest_pool.get('name'))

        dest_pool = dest_pool['name']

        old_export_location = share['export_locations'][0]

        share = self.migrate_share(share['id'], dest_pool, version='2.5')

        self.assertEqual(dest_pool, share['host'])
        self.assertNotEqual(old_export_location, share['export_locations'][0])
        self.assertEqual('migration_success', share['task_state'])
