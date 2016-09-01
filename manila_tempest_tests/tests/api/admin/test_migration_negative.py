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

import six

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test
import testtools

from manila_tempest_tests.common import constants
from manila_tempest_tests import share_exceptions
from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


class MigrationTest(base.BaseSharesAdminTest):
    """Tests Share Migration.

    Tests share migration in multi-backend environment.
    """

    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(MigrationTest, cls).resource_setup()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled." % cls.protocol
            raise cls.skipException(message)
        if not (CONF.share.run_host_assisted_migration_tests or
                CONF.share.run_driver_assisted_migration_tests):
            raise cls.skipException("Share migration tests are disabled.")

        pools = cls.shares_client.list_pools(detail=True)['pools']

        if len(pools) < 2:
            raise cls.skipException("At least two different pool entries "
                                    "are needed to run share migration tests.")

        cls.share = cls.create_share(cls.protocol)
        cls.share = cls.shares_client.get_share(cls.share['id'])

        default_type = cls.shares_v2_client.list_share_types(
            default=True)['share_type']

        dest_pool = utils.choose_matching_backend(
            cls.share, pools, default_type)

        if not dest_pool or dest_pool.get('name') is None:
            raise share_exceptions.ShareMigrationException(
                "No valid pool entries to run share migration tests.")

        cls.dest_pool = dest_pool['name']

        extra_specs = {
            'storage_protocol': CONF.share.capability_storage_protocol,
            'driver_handles_share_servers': CONF.share.multitenancy_enabled,
            'snapshot_support': six.text_type(
                not CONF.share.capability_snapshot_support),
        }
        cls.new_type = cls.create_share_type(
            name=data_utils.rand_name(
                'new_invalid_share_type_for_migration'),
            cleanup_in_class=True,
            extra_specs=extra_specs)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migration_cancel_invalid(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migration_cancel,
            self.share['id'])

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migration_get_progress_None(self):
        self.shares_v2_client.reset_task_state(self.share["id"], None)
        self.shares_v2_client.wait_for_share_status(
            self.share["id"], None, 'task_state')
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migration_get_progress,
            self.share['id'])

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migration_complete_invalid(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migration_complete,
            self.share['id'])

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migration_cancel_not_found(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migration_cancel,
            'invalid_share_id')

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migration_get_progress_not_found(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migration_get_progress,
            'invalid_share_id')

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migration_complete_not_found(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migration_complete,
            'invalid_share_id')

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_migrate_share_with_snapshot(self):
        snap = self.create_snapshot_wait_for_active(self.share['id'])
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool)
        self.shares_client.delete_snapshot(snap['id'])
        self.shares_client.wait_for_resource_deletion(snapshot_id=snap["id"])

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migrate_share_same_host(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.share['host'])

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migrate_share_host_invalid(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migrate_share,
            self.share['id'], 'invalid_host')

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migrate_share_host_assisted_not_allowed(self):
        self.shares_v2_client.migrate_share(
            self.share['id'], self.dest_pool,
            force_host_assisted_migration=True, writable=True,
            preserve_metadata=True)
        self.shares_v2_client.wait_for_migration_status(
            self.share['id'], self.dest_pool,
            constants.TASK_STATE_MIGRATION_ERROR)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migrate_share_change_type_no_valid_host(self):
        self.shares_v2_client.migrate_share(
            self.share['id'], self.dest_pool,
            new_share_type_id=self.new_type['share_type']['id'])
        self.shares_v2_client.wait_for_migration_status(
            self.share['id'], self.dest_pool,
            constants.TASK_STATE_MIGRATION_ERROR)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migrate_share_not_found(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migrate_share,
            'invalid_share_id', self.dest_pool)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migrate_share_not_available(self):
        self.shares_client.reset_state(self.share['id'],
                                       constants.STATUS_ERROR)
        self.shares_client.wait_for_share_status(self.share['id'],
                                                 constants.STATUS_ERROR)
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool)
        self.shares_client.reset_state(self.share['id'],
                                       constants.STATUS_AVAILABLE)
        self.shares_client.wait_for_share_status(self.share['id'],
                                                 constants.STATUS_AVAILABLE)

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migrate_share_invalid_share_network(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool,
            new_share_network_id='invalid_net_id')

    @test.attr(type=[base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    def test_migrate_share_invalid_share_type(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool, True,
            new_share_type_id='invalid_type_id')
