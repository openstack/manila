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


import ddt
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
import testtools
from testtools import testcase as tc

from manila_tempest_tests.common import constants
from manila_tempest_tests import share_exceptions
from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


@ddt.ddt
class MigrationNegativeTest(base.BaseSharesAdminTest):
    """Tests Share Migration.

    Tests share migration in multi-backend environment.
    """

    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(MigrationNegativeTest, cls).resource_setup()
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

        cls.default_type = cls.shares_v2_client.list_share_types(
            default=True)['share_type']

        dest_pool = utils.choose_matching_backend(
            cls.share, pools, cls.default_type)

        if not dest_pool or dest_pool.get('name') is None:
            raise share_exceptions.ShareMigrationException(
                "No valid pool entries to run share migration tests.")

        cls.dest_pool = dest_pool['name']

        cls.new_type_invalid = cls.create_share_type(
            name=data_utils.rand_name(
                'new_invalid_share_type_for_migration'),
            cleanup_in_class=True,
            extra_specs=utils.get_configured_extra_specs(variation='invalid'))

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.22")
    def test_migration_cancel_invalid(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migration_cancel,
            self.share['id'])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.22")
    def test_migration_get_progress_None(self):
        self.shares_v2_client.reset_task_state(self.share["id"], None)
        self.shares_v2_client.wait_for_share_status(
            self.share["id"], None, 'task_state')
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migration_get_progress,
            self.share['id'])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.22")
    def test_migration_complete_invalid(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migration_complete,
            self.share['id'])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.22")
    def test_migration_cancel_not_found(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migration_cancel,
            'invalid_share_id')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.22")
    def test_migration_get_progress_not_found(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migration_get_progress,
            'invalid_share_id')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.22")
    def test_migration_complete_not_found(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migration_complete,
            'invalid_share_id')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_migrate_share_with_snapshot(self):
        snap = self.create_snapshot_wait_for_active(self.share['id'])
        self.assertRaises(
            lib_exc.Conflict, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool,
            force_host_assisted_migration=True)
        self.shares_client.delete_snapshot(snap['id'])
        self.shares_client.wait_for_resource_deletion(snapshot_id=snap["id"])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @ddt.data(True, False)
    def test_migrate_share_same_host(self, specified):
        new_share_type_id = None
        new_share_network_id = None
        if specified:
            new_share_type_id = self.default_type['id']
            new_share_network_id = self.share['share_network_id']
        self.migrate_share(
            self.share['id'], self.share['host'],
            wait_for_status=constants.TASK_STATE_MIGRATION_SUCCESS,
            new_share_type_id=new_share_type_id,
            new_share_network_id=new_share_network_id)
        # NOTE(ganso): No need to assert, it is already waiting for correct
        # status (migration_success).

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    def test_migrate_share_host_invalid(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migrate_share,
            self.share['id'], 'invalid_host')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @ddt.data({'writable': False, 'preserve_metadata': False,
               'preserve_snapshots': False, 'nondisruptive': True},
              {'writable': False, 'preserve_metadata': False,
               'preserve_snapshots': True, 'nondisruptive': False},
              {'writable': False, 'preserve_metadata': True,
               'preserve_snapshots': False, 'nondisruptive': False},
              {'writable': True, 'preserve_metadata': False,
               'preserve_snapshots': False, 'nondisruptive': False})
    @ddt.unpack
    def test_migrate_share_host_assisted_not_allowed_API(
            self, writable, preserve_metadata, preserve_snapshots,
            nondisruptive):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool,
            force_host_assisted_migration=True, writable=writable,
            preserve_metadata=preserve_metadata, nondisruptive=nondisruptive,
            preserve_snapshots=preserve_snapshots)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    def test_migrate_share_change_type_no_valid_host(self):
        if not CONF.share.multitenancy_enabled:
            new_share_network_id = self.create_share_network(
                neutron_net_id='fake_net_id',
                neutron_subnet_id='fake_subnet_id')['id']
        else:
            new_share_network_id = None

        self.shares_v2_client.migrate_share(
            self.share['id'], self.dest_pool,
            new_share_type_id=self.new_type_invalid['share_type']['id'],
            new_share_network_id=new_share_network_id)
        self.shares_v2_client.wait_for_migration_status(
            self.share['id'], self.dest_pool,
            constants.TASK_STATE_MIGRATION_ERROR)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    def test_migrate_share_not_found(self):
        self.assertRaises(
            lib_exc.NotFound, self.shares_v2_client.migrate_share,
            'invalid_share_id', self.dest_pool)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
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

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    def test_migrate_share_invalid_share_network(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool,
            new_share_network_id='invalid_net_id')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    def test_migrate_share_invalid_share_type(self):
        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool,
            new_share_type_id='invalid_type_id')

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    def test_migrate_share_opposite_type_share_network_invalid(self):

        extra_specs = utils.get_configured_extra_specs(
            variation='opposite_driver_modes')

        new_type_opposite = self.create_share_type(
            name=data_utils.rand_name('share_type_migration_negative'),
            extra_specs=extra_specs)

        new_share_network_id = None

        if CONF.share.multitenancy_enabled:

            new_share_network_id = self.create_share_network(
                neutron_net_id='fake_net_id',
                neutron_subnet_id='fake_subnet_id')['id']

        self.assertRaises(
            lib_exc.BadRequest, self.shares_v2_client.migrate_share,
            self.share['id'], self.dest_pool,
            new_share_type_id=new_type_opposite['share_type']['id'],
            new_share_network_id=new_share_network_id)
