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

import ddt
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test

from manila_tempest_tests.common import constants
from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


@ddt.ddt
class MigrationNFSTest(base.BaseSharesAdminTest):
    """Tests Share Migration for NFS shares.

    Tests share migration in multi-backend environment.

    This class covers:
    1) Driver-assisted migration: force_host_assisted_migration, nondisruptive,
    writable and preserve-metadata are False.
    2) Host-assisted migration: force_host_assisted_migration is True,
    nondisruptive, writable and preserve-metadata are False.
    3) 2-phase migration of both Host-assisted and Driver-assisted.

    No need to test with writable, preserve-metadata and non-disruptive as
    True, values are supplied to the driver which decides what to do. Test
    should be positive, so not being writable, not preserving metadata and
    being disruptive is less restrictive for drivers, which would abort if they
    cannot handle them.

    Drivers that implement driver-assisted migration should enable the
    configuration flag to be tested.
    """

    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(MigrationNFSTest, cls).resource_setup()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled." % cls.protocol
            raise cls.skipException(message)
        if not (CONF.share.run_host_assisted_migration_tests or
                CONF.share.run_driver_assisted_migration_tests):
            raise cls.skipException("Share migration tests are disabled.")

        extra_specs = {
            'storage_protocol': CONF.share.capability_storage_protocol,
            'driver_handles_share_servers': (
                CONF.share.multitenancy_enabled),
            'snapshot_support': six.text_type(
                CONF.share.capability_snapshot_support),
        }
        cls.new_type = cls.create_share_type(
            name=data_utils.rand_name('new_share_type_for_migration'),
            cleanup_in_class=True,
            extra_specs=extra_specs)

    @test.attr(type=[base.TAG_POSITIVE, base.TAG_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    @ddt.data(True, False)
    def test_migration_cancel(self, force_host_assisted):

        self._check_migration_enabled(force_host_assisted)

        share, dest_pool = self._setup_migration()

        old_exports = self.shares_v2_client.list_share_export_locations(
            share['id'])
        self.assertNotEmpty(old_exports)
        old_exports = [x['path'] for x in old_exports
                       if x['is_admin_only'] is False]
        self.assertNotEmpty(old_exports)

        task_state = (constants.TASK_STATE_DATA_COPYING_COMPLETED
                      if force_host_assisted
                      else constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)

        share = self.migrate_share(
            share['id'], dest_pool, wait_for_status=task_state,
            force_host_assisted_migration=force_host_assisted)

        self._validate_migration_successful(
            dest_pool, share, task_state, complete=False)

        share = self.migration_cancel(share['id'], dest_pool)

        self._validate_migration_successful(
            dest_pool, share, constants.TASK_STATE_MIGRATION_CANCELLED,
            complete=False)

    @test.attr(type=[base.TAG_POSITIVE, base.TAG_BACKEND])
    @base.skip_if_microversion_lt("2.22")
    @ddt.data(True, False)
    def test_migration_2phase(self, force_host_assisted):

        self._check_migration_enabled(force_host_assisted)

        share, dest_pool = self._setup_migration()

        old_exports = self.shares_v2_client.list_share_export_locations(
            share['id'])
        self.assertNotEmpty(old_exports)
        old_exports = [x['path'] for x in old_exports
                       if x['is_admin_only'] is False]
        self.assertNotEmpty(old_exports)

        task_state = (constants.TASK_STATE_DATA_COPYING_COMPLETED
                      if force_host_assisted
                      else constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)

        old_share_network_id = share['share_network_id']
        new_share_network_id = self._create_secondary_share_network(
            old_share_network_id)
        old_share_type_id = share['share_type']
        new_share_type_id = self.new_type['share_type']['id']

        share = self.migrate_share(
            share['id'], dest_pool,
            force_host_assisted_migration=force_host_assisted,
            wait_for_status=task_state, new_share_type_id=new_share_type_id,
            new_share_network_id=new_share_network_id)

        self._validate_migration_successful(
            dest_pool, share, task_state, complete=False,
            share_network_id=old_share_network_id,
            share_type_id=old_share_type_id)

        progress = self.shares_v2_client.migration_get_progress(share['id'])

        self.assertEqual(task_state, progress['task_state'])
        self.assertEqual(100, progress['total_progress'])

        share = self.migration_complete(share['id'], dest_pool)

        self._validate_migration_successful(
            dest_pool, share, constants.TASK_STATE_MIGRATION_SUCCESS,
            complete=True, share_network_id=new_share_network_id,
            share_type_id=new_share_type_id)

    def _setup_migration(self):

        pools = self.shares_v2_client.list_pools(detail=True)['pools']

        if len(pools) < 2:
            raise self.skipException("At least two different pool entries are "
                                     "needed to run share migration tests.")

        share = self.create_share(self.protocol)
        share = self.shares_v2_client.get_share(share['id'])

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

    def _validate_migration_successful(self, dest_pool, share, status_to_wait,
                                       version=CONF.share.max_api_microversion,
                                       complete=True, share_network_id=None,
                                       share_type_id=None):

        statuses = ((status_to_wait,)
                    if not isinstance(status_to_wait, (tuple, list, set))
                    else status_to_wait)

        new_exports = self.shares_v2_client.list_share_export_locations(
            share['id'], version=version)
        self.assertNotEmpty(new_exports)
        new_exports = [x['path'] for x in new_exports if
                       x['is_admin_only'] is False]
        self.assertNotEmpty(new_exports)

        self.assertIn(share['task_state'], statuses)
        if share_network_id:
            self.assertEqual(share_network_id, share['share_network_id'])
        if share_type_id:
            self.assertEqual(share_type_id, share['share_type'])

        # Share migrated
        if complete:
            self.assertEqual(dest_pool, share['host'])
            self.shares_v2_client.delete_share(share['id'])
            self.shares_v2_client.wait_for_resource_deletion(
                share_id=share['id'])
        # Share not migrated yet
        else:
            self.assertNotEqual(dest_pool, share['host'])

    def _check_migration_enabled(self, force_host_assisted):

        if force_host_assisted:
            if not CONF.share.run_host_assisted_migration_tests:
                raise self.skipException(
                    "Host-assisted migration tests are disabled.")
        else:
            if not CONF.share.run_driver_assisted_migration_tests:
                raise self.skipException(
                    "Driver-assisted migration tests are disabled.")

    def _create_secondary_share_network(self, old_share_network_id):
        if (utils.is_microversion_ge(
                CONF.share.max_api_microversion, "2.22") and
                CONF.share.multitenancy_enabled):

            old_share_network = self.shares_v2_client.get_share_network(
                old_share_network_id)

            new_share_network = self.create_share_network(
                cleanup_in_class=True,
                neutron_net_id=old_share_network['neutron_net_id'],
                neutron_subnet_id=old_share_network['neutron_subnet_id'])

            return new_share_network['id']
        else:
            return None
