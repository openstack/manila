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
import testtools
from testtools import testcase as tc

from manila_tempest_tests.common import constants
from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


class MigrationBase(base.BaseSharesAdminTest):
    """Base test class for Share Migration.

    Tests share migration in multi-backend environment.

    This class covers:
    1) Driver-assisted migration: force_host_assisted_migration, nondisruptive,
    writable and preserve-metadata are False.
    2) Host-assisted migration: force_host_assisted_migration is True,
    nondisruptive, writable, preserve-metadata and preserve-snapshots are
    False.
    3) 2-phase migration of both Host-assisted and Driver-assisted.
    4) Cancelling migration past first phase.
    5) Changing driver modes through migration.

    No need to test with writable, preserve-metadata and non-disruptive as
    True, values are supplied to the driver which decides what to do. Test
    should be positive, so not being writable, not preserving metadata and
    being disruptive is less restrictive for drivers, which would abort if they
    cannot handle them.

    Drivers that implement driver-assisted migration should enable the
    configuration flag to be tested.
    """

    protocol = None

    @classmethod
    def resource_setup(cls):
        super(MigrationBase, cls).resource_setup()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled." % cls.protocol
            raise cls.skipException(message)
        if not (CONF.share.run_host_assisted_migration_tests or
                CONF.share.run_driver_assisted_migration_tests):
            raise cls.skipException("Share migration tests are disabled.")
        cls.pools = cls.shares_v2_client.list_pools(detail=True)['pools']

        if len(cls.pools) < 2:
            raise cls.skipException("At least two different pool entries are "
                                    "needed to run share migration tests.")

        # create share type (generic)
        cls.share_type = cls._create_share_type()
        cls.share_type_id = cls.share_type['id']

        cls.new_type = cls.create_share_type(
            name=data_utils.rand_name('new_share_type_for_migration'),
            cleanup_in_class=True,
            extra_specs=utils.get_configured_extra_specs())

        cls.new_type_opposite = cls.create_share_type(
            name=data_utils.rand_name('new_share_type_for_migration_opposite'),
            cleanup_in_class=True,
            extra_specs=utils.get_configured_extra_specs(
                variation='opposite_driver_modes'))

    def _setup_migration(self, share, opposite=False):

        if opposite:
            dest_type = self.new_type_opposite['share_type']
        else:
            dest_type = self.new_type['share_type']

        dest_pool = utils.choose_matching_backend(share, self.pools, dest_type)

        if opposite:
            if not dest_pool:
                raise self.skipException(
                    "This test requires two pools enabled with different "
                    "driver modes.")
        else:
            self.assertIsNotNone(dest_pool)
            self.assertIsNotNone(dest_pool.get('name'))

        old_exports = self.shares_v2_client.list_share_export_locations(
            share['id'])
        self.assertNotEmpty(old_exports)
        old_exports = [x['path'] for x in old_exports
                       if x['is_admin_only'] is False]
        self.assertNotEmpty(old_exports)

        self.shares_v2_client.create_access_rule(
            share['id'], access_to="50.50.50.50", access_level="rw")

        self.shares_v2_client.wait_for_share_status(
            share['id'], constants.RULE_STATE_ACTIVE,
            status_attr='access_rules_status')

        self.shares_v2_client.create_access_rule(
            share['id'], access_to="51.51.51.51", access_level="ro")

        self.shares_v2_client.wait_for_share_status(
            share['id'], constants.RULE_STATE_ACTIVE,
            status_attr='access_rules_status')

        dest_pool = dest_pool['name']
        share = self.shares_v2_client.get_share(share['id'])

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

            rules = self.shares_v2_client.list_access_rules(share['id'])
            expected_rules = [{
                'state': constants.RULE_STATE_ACTIVE,
                'access_to': '50.50.50.50',
                'access_type': 'ip',
                'access_level': 'rw',
            }, {
                'state': constants.RULE_STATE_ACTIVE,
                'access_to': '51.51.51.51',
                'access_type': 'ip',
                'access_level': 'ro',
            }]
            filtered_rules = [{'state': rule['state'],
                               'access_to': rule['access_to'],
                               'access_level': rule['access_level'],
                               'access_type': rule['access_type']}
                              for rule in rules]

            for r in expected_rules:
                self.assertIn(r, filtered_rules)
            self.assertEqual(len(expected_rules), len(filtered_rules))

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

        old_share_network = self.shares_v2_client.get_share_network(
            old_share_network_id)

        new_share_network = self.create_share_network(
            cleanup_in_class=True,
            neutron_net_id=old_share_network['neutron_net_id'],
            neutron_subnet_id=old_share_network['neutron_subnet_id'])

        return new_share_network['id']

    def _test_resize_post_migration(self, force_host_assisted, resize):
        self._check_migration_enabled(force_host_assisted)
        new_size = CONF.share.share_size + 1
        share = self.create_share(self.protocol,
                                  size=new_size,
                                  share_type_id=self.share_type_id)
        share = self.shares_v2_client.get_share(share['id'])

        share, dest_pool = self._setup_migration(share)

        task_state, new_share_network_id, new_share_type_id = (
            self._get_migration_data(share, force_host_assisted))

        share = self.migrate_share(
            share['id'], dest_pool,
            force_host_assisted_migration=force_host_assisted,
            wait_for_status=task_state, new_share_type_id=new_share_type_id,
            new_share_network_id=new_share_network_id)

        share = self.migration_complete(share['id'], dest_pool)
        if resize == 'extend':
            new_size = CONF.share.share_size + 2
            self.shares_v2_client.extend_share(share['id'], new_size)
            self.shares_v2_client.wait_for_share_status(
                share['id'], constants.STATUS_AVAILABLE)
            share = self.shares_v2_client.get_share(share["id"])
            self.assertEqual(new_size, int(share["size"]))
        else:
            new_size = CONF.share.share_size
            self.shares_v2_client.shrink_share(share['id'], new_size)
            self.shares_v2_client.wait_for_share_status(
                share['id'], constants.STATUS_AVAILABLE)
            share = self.shares_v2_client.get_share(share["id"])
            self.assertEqual(new_size, int(share["size"]))

        self._cleanup_share(share)

    def _get_migration_data(self, share, force_host_assisted=False):
        task_state = (constants.TASK_STATE_DATA_COPYING_COMPLETED
                      if force_host_assisted
                      else constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)

        old_share_network_id = share['share_network_id']

        if CONF.share.multitenancy_enabled:
            new_share_network_id = self._create_secondary_share_network(
                old_share_network_id)

        else:
            new_share_network_id = None

        new_share_type_id = self.new_type['share_type']['id']
        return task_state, new_share_network_id, new_share_type_id

    def _validate_snapshot(self, share, snapshot1, snapshot2):
        snapshot_list = self.shares_v2_client.list_snapshots_for_share(
            share['id'])
        msg = "Share %s has no snapshot." % share['id']
        # Verify that snapshot list is not empty
        self.assertNotEmpty(snapshot_list, msg)
        snapshot_id_list = [snap['id'] for snap in snapshot_list]

        # Verify that after migration original snapshots are retained
        self.assertIn(snapshot1['id'], snapshot_id_list)
        self.assertIn(snapshot2['id'], snapshot_id_list)
        # Verify that a share can be created from a snapshot after migration
        snapshot1_share = self.create_share(
            self.protocol,
            size=share['size'],
            snapshot_id=snapshot1['id'],
            share_network_id=share['share_network_id'])
        self.assertEqual(snapshot1['id'], snapshot1_share['snapshot_id'])
        self._cleanup_share(share)

    def _validate_share_migration_with_different_snapshot_capability_type(
            self, force_host_assisted, snapshot_capable):

        self._check_migration_enabled(force_host_assisted)
        ss_type, no_ss_type = self._create_share_type_for_snapshot_capability()

        if snapshot_capable:
            share_type = ss_type['share_type']
            share_type_id = no_ss_type['share_type']['id']
            new_share_type_id = ss_type['share_type']['id']
        else:
            share_type = no_ss_type['share_type']
            share_type_id = ss_type['share_type']['id']
            new_share_type_id = no_ss_type['share_type']['id']

        share = self.create_share(
            self.protocol, share_type_id=share_type_id)
        share = self.shares_v2_client.get_share(share['id'])

        if snapshot_capable:
            self.assertEqual(False, share['snapshot_support'])
        else:
            # Verify that share has snapshot support capability
            self.assertTrue(share['snapshot_support'])

        dest_pool = utils.choose_matching_backend(share, self.pools,
                                                  share_type)
        task_state, new_share_network_id, __ = (
            self._get_migration_data(share, force_host_assisted))
        share = self.migrate_share(
            share['id'], dest_pool['name'],
            force_host_assisted_migration=force_host_assisted,
            wait_for_status=task_state,
            new_share_type_id=new_share_type_id,
            new_share_network_id=new_share_network_id)
        share = self.migration_complete(share['id'], dest_pool)

        if snapshot_capable:
            # Verify that migrated share does have snapshot support capability
            self.assertTrue(share['snapshot_support'])
        else:
            # Verify that migrated share don't have snapshot support capability
            self.assertEqual(False, share['snapshot_support'])

        self._cleanup_share(share)

    def _create_share_type_for_snapshot_capability(self):
        # Share type with snapshot support
        st_name = data_utils.rand_name(
            'snapshot_capable_share_type_for_migration')
        extra_specs = self.add_extra_specs_to_dict({"snapshot_support": True})
        ss_type = self.create_share_type(st_name, extra_specs=extra_specs)

        # New share type with no snapshot support capability
        # to which a share will be migrated
        new_st_name = data_utils.rand_name(
            'snapshot_noncapable_share_type_for_migration')
        extra_specs = {
            "driver_handles_share_servers": CONF.share.multitenancy_enabled
        }
        no_ss_type = self.create_share_type(new_st_name,
                                            extra_specs=extra_specs)
        return ss_type, no_ss_type

    def _cleanup_share(self, share):
        resource = {"type": "share", "id": share["id"],
                    "client": self.shares_v2_client}
        # NOTE(Yogi1): Share needs to be cleaned up explicitly at the end of
        #  test otherwise, newly created share_network will not get cleaned up.
        self.method_resources.insert(0, resource)


@ddt.ddt
class MigrationCancelNFSTest(MigrationBase):
    protocol = "nfs"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @ddt.data(True, False)
    def test_migration_cancel(self, force_host_assisted):
        self._check_migration_enabled(force_host_assisted)

        share = self.create_share(self.protocol,
                                  share_type_id=self.share_type_id)
        share = self.shares_v2_client.get_share(share['id'])
        share, dest_pool = self._setup_migration(share)
        task_state = (constants.TASK_STATE_DATA_COPYING_COMPLETED
                      if force_host_assisted
                      else constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)

        share = self.migrate_share(
            share['id'], dest_pool, wait_for_status=task_state,
            force_host_assisted_migration=force_host_assisted)

        self._validate_migration_successful(
            dest_pool, share, task_state, complete=False)

        progress = self.shares_v2_client.migration_get_progress(share['id'])

        self.assertEqual(task_state, progress['task_state'])
        self.assertEqual(100, progress['total_progress'])

        share = self.migration_cancel(share['id'], dest_pool)
        progress = self.shares_v2_client.migration_get_progress(share['id'])

        self.assertEqual(
            constants.TASK_STATE_MIGRATION_CANCELLED, progress['task_state'])
        self.assertEqual(100, progress['total_progress'])

        self._validate_migration_successful(
            dest_pool, share, constants.TASK_STATE_MIGRATION_CANCELLED,
            complete=False)

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @testtools.skipUnless(
        CONF.share.run_snapshot_tests, 'Snapshot tests are disabled.')
    @testtools.skipUnless(
        CONF.share.run_driver_assisted_migration_tests,
        'Driver-assisted migration tests are disabled.')
    @testtools.skipUnless(
        CONF.share.run_migration_with_preserve_snapshots_tests,
        'Migration with preserve snapshots tests are disabled.')
    def test_migration_cancel_share_with_snapshot(self):
        share = self.create_share(self.protocol,
                                  share_type_id=self.share_type_id)
        share = self.shares_v2_client.get_share(share['id'])

        share, dest_pool = self._setup_migration(share)
        snapshot1 = self.create_snapshot_wait_for_active(share['id'])
        snapshot2 = self.create_snapshot_wait_for_active(share['id'])

        task_state, new_share_network_id, new_share_type_id = (
            self._get_migration_data(share))

        share = self.migrate_share(
            share['id'], dest_pool,
            wait_for_status=task_state, new_share_type_id=new_share_type_id,
            new_share_network_id=new_share_network_id, preserve_snapshots=True)

        share = self.migration_cancel(share['id'], dest_pool)
        self._validate_snapshot(share, snapshot1, snapshot2)


@ddt.ddt
class MigrationOppositeDriverModesNFSTest(MigrationBase):
    protocol = "nfs"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @ddt.data(True, False)
    def test_migration_opposite_driver_modes(self, force_host_assisted):
        self._check_migration_enabled(force_host_assisted)

        share = self.create_share(self.protocol,
                                  share_type_id=self.share_type_id)
        share = self.shares_v2_client.get_share(share['id'])
        share, dest_pool = self._setup_migration(share, opposite=True)

        if not CONF.share.multitenancy_enabled:
            # If currently configured is DHSS=False,
            # then we need it for DHSS=True
            new_share_network_id = self.provide_share_network(
                self.shares_v2_client,
                self.networks_client,
                isolated_creds_client=None,
                ignore_multitenancy_config=True,
            )
        else:
            # If currently configured is DHSS=True,
            # then we must pass None for DHSS=False
            new_share_network_id = None

        old_share_network_id = share['share_network_id']
        old_share_type_id = share['share_type']
        new_share_type_id = self.new_type_opposite['share_type']['id']

        task_state = (constants.TASK_STATE_DATA_COPYING_COMPLETED
                      if force_host_assisted
                      else constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)

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

        progress = self.shares_v2_client.migration_get_progress(share['id'])

        self.assertEqual(
            constants.TASK_STATE_MIGRATION_SUCCESS, progress['task_state'])
        self.assertEqual(100, progress['total_progress'])

        self._validate_migration_successful(
            dest_pool, share, constants.TASK_STATE_MIGRATION_SUCCESS,
            complete=True, share_network_id=new_share_network_id,
            share_type_id=new_share_type_id)


@ddt.ddt
class MigrationTwoPhaseNFSTest(MigrationBase):
    protocol = "nfs"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @ddt.data(True, False)
    def test_migration_2phase(self, force_host_assisted):
        self._check_migration_enabled(force_host_assisted)

        share = self.create_share(self.protocol,
                                  share_type_id=self.share_type_id)
        share = self.shares_v2_client.get_share(share['id'])
        share, dest_pool = self._setup_migration(share)

        old_share_network_id = share['share_network_id']
        old_share_type_id = share['share_type']
        task_state, new_share_network_id, new_share_type_id = (
            self._get_migration_data(share, force_host_assisted))

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

        progress = self.shares_v2_client.migration_get_progress(share['id'])

        self.assertEqual(
            constants.TASK_STATE_MIGRATION_SUCCESS, progress['task_state'])
        self.assertEqual(100, progress['total_progress'])

        self._validate_migration_successful(
            dest_pool, share, constants.TASK_STATE_MIGRATION_SUCCESS,
            complete=True, share_network_id=new_share_network_id,
            share_type_id=new_share_type_id)
        self._cleanup_share(share)


@ddt.ddt
class MigrationWithShareExtendingNFSTest(MigrationBase):
    protocol = "nfs"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @testtools.skipUnless(
        CONF.share.run_extend_tests, 'Extend share tests are disabled.')
    @ddt.data(True, False)
    def test_extend_on_migrated_share(self, force_host_assisted):
        self._test_resize_post_migration(force_host_assisted, resize='extend')


@ddt.ddt
class MigrationWithShareShrinkingNFSTest(MigrationBase):
    protocol = "nfs"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @testtools.skipUnless(
        CONF.share.run_shrink_tests, 'Shrink share tests are disabled.')
    @ddt.data(True, False)
    def test_shrink_on_migrated_share(self, force_host_assisted):
        self._test_resize_post_migration(force_host_assisted, resize='shrink')


@ddt.ddt
class MigrationOfShareWithSnapshotNFSTest(MigrationBase):
    protocol = "nfs"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @testtools.skipUnless(
        CONF.share.run_snapshot_tests, 'Snapshot tests are disabled.')
    @testtools.skipUnless(
        CONF.share.run_driver_assisted_migration_tests,
        'Driver-assisted migration tests are disabled.')
    @testtools.skipUnless(
        CONF.share.run_migration_with_preserve_snapshots_tests,
        'Migration with preserve snapshots tests are disabled.')
    def test_migrating_share_with_snapshot(self):
        ss_type, __ = self._create_share_type_for_snapshot_capability()

        share = self.create_share(self.protocol,
                                  share_type_id=ss_type['share_type']['id'],
                                  cleanup_in_class=False)
        share = self.shares_v2_client.get_share(share['id'])

        share, dest_pool = self._setup_migration(share)
        snapshot1 = self.create_snapshot_wait_for_active(
            share['id'], cleanup_in_class=False)
        snapshot2 = self.create_snapshot_wait_for_active(
            share['id'], cleanup_in_class=False)

        task_state, new_share_network_id, __ = self._get_migration_data(share)

        share = self.migrate_share(
            share['id'], dest_pool,
            wait_for_status=task_state,
            new_share_type_id=ss_type['share_type']['id'],
            new_share_network_id=new_share_network_id, preserve_snapshots=True)

        share = self.migration_complete(share['id'], dest_pool)

        self._validate_snapshot(share, snapshot1, snapshot2)


@ddt.ddt
class MigrationWithDifferentSnapshotSupportNFSTest(MigrationBase):
    protocol = "nfs"

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          'Snapshot tests are disabled.')
    @ddt.data(True, False)
    def test_migrate_share_to_snapshot_capability_share_type(
            self, force_host_assisted):
        # Verify that share with no snapshot support type can be migrated
        # to new share type which supports the snapshot
        self._validate_share_migration_with_different_snapshot_capability_type(
            force_host_assisted, True)

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          'Snapshot tests are disabled.')
    @ddt.data(True, False)
    def test_migrate_share_to_no_snapshot_capability_share_type(
            self, force_host_assisted):
        # Verify that share with snapshot support type can be migrated
        # to new share type which doesn't support the snapshot
        self._validate_share_migration_with_different_snapshot_capability_type(
            force_host_assisted, False)


# NOTE(u_glide): this function is required to exclude MigrationBase from
# executed test cases.
# See: https://docs.python.org/2/library/unittest.html#load-tests-protocol
# for details.
def load_tests(loader, tests, _):
    result = []
    for test_case in tests:
        if not test_case._tests or type(test_case._tests[0]) is MigrationBase:
            continue
        result.append(test_case)
    return loader.suiteClass(result)
