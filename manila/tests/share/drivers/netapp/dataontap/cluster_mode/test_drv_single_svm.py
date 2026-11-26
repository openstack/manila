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
"""
Unit tests for the NetApp Data ONTAP cDOT single-SVM share driver shim.

The driver is a passthrough layer over the single-SVM storage library, so the
tests assert the delegation contract: which library call each driver method
makes, in which argument order, and whether the library result is returned.
Several methods deliberately drop or reorder arguments, and those are covered
individually because a silent change there is not caught by a signature check.
"""

from unittest import mock

import ddt

from manila.share import driver
from manila.share.drivers.netapp.dataontap.cluster_mode import drv_single_svm
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_single_svm
from manila import test


S = mock.sentinel


@ddt.ddt
class NetAppCmodeSingleSvmShareDriverTestCase(test.TestCase):

    def setUp(self):
        super(NetAppCmodeSingleSvmShareDriverTestCase, self).setUp()

        self.mock_object(driver.ShareDriver, '__init__',
                         mock.Mock(return_value=None))
        self.mock_library_cls = self.mock_object(
            lib_single_svm, 'NetAppCmodeSingleSVMFileStorageLibrary')

        self.driver = drv_single_svm.NetAppCmodeSingleSvmShareDriver(
            configuration=S.configuration)
        self.library = self.driver.library

    # ------------------------------------------------------------------ init
    def test_init(self):
        self.assertEqual(self.mock_library_cls.return_value,
                         self.driver.library)
        self.assertEqual({},
                         self.driver
                         .dhss_mandatory_security_service_association)
        self.assertTrue(self.driver.qos_type_support)

    def test_init_builds_library_without_share_server_handling(self):
        driver.ShareDriver.__init__.assert_called_once_with(
            False, configuration=S.configuration)
        self.mock_library_cls.assert_called_once_with(
            drv_single_svm.NetAppCmodeSingleSvmShareDriver.DRIVER_NAME,
            configuration=S.configuration)

    # ------------------------------------------------- plain delegation table
    # (driver method, driver args, library method, expected library args,
    #  expected library kwargs, driver returns the library result)
    @ddt.data(
        ('do_setup', (S.context,), 'do_setup', (S.context,), {}, False),
        ('check_for_setup_error', (), 'check_for_setup_error', (), {}, False),
        ('get_pool', (S.share,), 'get_pool', (S.share,), {}, True),
        ('create_share', (S.context, S.share), 'create_share',
         (S.context, S.share), {}, True),
        ('create_share_from_snapshot', (S.context, S.share, S.snapshot),
         'create_share_from_snapshot', (S.context, S.share, S.snapshot),
         {}, True),
        ('create_snapshot', (S.context, S.snapshot), 'create_snapshot',
         (S.context, S.snapshot), {}, True),
        ('delete_share', (S.context, S.share), 'delete_share',
         (S.context, S.share), {}, False),
        ('delete_snapshot', (S.context, S.snapshot), 'delete_snapshot',
         (S.context, S.snapshot), {}, False),
        ('extend_share', (S.share, S.new_size), 'extend_share',
         (S.share, S.new_size), {}, False),
        ('shrink_share', (S.share, S.new_size), 'shrink_share',
         (S.share, S.new_size), {}, False),
        ('manage_existing', (S.share, S.driver_options), 'manage_existing',
         (S.share, S.driver_options), {}, True),
        ('unmanage', (S.share,), 'unmanage', (S.share,), {}, False),
        ('manage_existing_snapshot', (S.snapshot, S.driver_options),
         'manage_existing_snapshot', (S.snapshot, S.driver_options), {}, True),
        ('unmanage_snapshot', (S.snapshot,), 'unmanage_snapshot',
         (S.snapshot,), {}, False),
        ('update_access',
         (S.context, S.share, S.rules, S.add, S.delete, S.update),
         'update_access',
         (S.context, S.share, S.rules, S.add, S.delete, S.update), {}, False),
        ('get_default_goodness_function', (), 'get_default_goodness_function',
         (), {}, True),
        ('get_share_server_pools', (S.share_server,),
         'get_share_server_pools', (S.share_server,), {}, True),
        ('get_network_allocations_number', (),
         'get_network_allocations_number', (), {}, True),
        ('get_admin_network_allocations_number', (),
         'get_admin_network_allocations_number', (), {}, True),
        ('get_configured_ip_versions', (), 'get_configured_ip_versions',
         (), {}, True),
        ('get_backend_info', (S.context,), 'get_backend_info',
         (S.context,), {}, True),
        ('ensure_shares', (S.context, S.shares), 'ensure_shares',
         (S.context, S.shares), {}, True),
        ('get_share_status', (S.share_instance, S.share_server),
         'get_share_status', (S.share_instance, S.share_server), {}, True),
        ('create_backup', (S.context, S.share, S.backup), 'create_backup',
         (S.context, S.share, S.backup), {}, True),
        ('create_backup_continue', (S.context, S.share, S.backup),
         'create_backup_continue', (S.context, S.share, S.backup), {}, True),
        ('restore_backup', (S.context, S.backup, S.share), 'restore_backup',
         (S.context, S.backup, S.share), {}, True),
        ('restore_backup_continue', (S.context, S.backup, S.share),
         'restore_backup_continue', (S.context, S.backup, S.share), {}, True),
        ('delete_backup', (S.context, S.backup, S.share), 'delete_backup',
         (S.context, S.backup, S.share), {}, True),
        ('get_default_filter_function', (), 'get_default_filter_function',
         (), {'pool': None}, True),
        ('promote_replica',
         (S.context, S.replica_list, S.replica, S.access_rules),
         'promote_replica',
         (S.context, S.replica_list, S.replica, S.access_rules),
         {'share_server': None, 'quiesce_wait_time': None}, True),
        ('update_replica_state',
         (S.context, S.replica_list, S.replica, S.access_rules,
          S.replica_snapshots),
         'update_replica_state',
         (S.context, S.replica_list, S.replica, S.access_rules,
          S.replica_snapshots), {'share_server': None}, True),
        ('create_replicated_snapshot',
         (S.context, S.replica_list, S.replica_snapshots),
         'create_replicated_snapshot',
         (S.context, S.replica_list, S.replica_snapshots),
         {'share_server': None}, True),
        ('delete_replicated_snapshot',
         (S.context, S.replica_list, S.replica_snapshots),
         'delete_replicated_snapshot',
         (S.context, S.replica_list, S.replica_snapshots),
         {'share_server': None}, True),
        ('create_replica',
         (S.context, S.replica_list, S.replica, S.access_rules,
          S.replica_snapshots),
         'create_replica',
         (S.context, S.replica_list, S.replica, S.access_rules,
          S.replica_snapshots), {}, True),
        ('update_share_from_metadata', (S.context, S.share, S.metadata),
         'update_share_from_metadata', (S.context, S.share, S.metadata),
         {'share_server': None}, False),
        ('migration_check_compatibility',
         (S.context, S.source_share, S.destination_share),
         'migration_check_compatibility',
         (S.context, S.source_share, S.destination_share),
         {'share_server': None, 'destination_share_server': None}, True),
        ('migration_start',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         'migration_start',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         {'share_server': None, 'destination_share_server': None}, True),
        ('migration_continue',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         'migration_continue',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         {'share_server': None, 'destination_share_server': None}, True),
        ('migration_get_progress',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         'migration_get_progress',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         {'share_server': None, 'destination_share_server': None}, True),
        ('migration_cancel',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         'migration_cancel',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         {'share_server': None, 'destination_share_server': None}, True),
        ('migration_complete',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         'migration_complete',
         (S.context, S.source_share, S.destination_share, S.source_snapshots,
          S.snapshot_mappings),
         {'share_server': None, 'destination_share_server': None}, True),
    )
    @ddt.unpack
    def test_delegates_to_library(self, method, args, lib_method,
                                  expected_args, expected_kwargs, returns):
        lib_call = getattr(self.library, lib_method)
        lib_call.return_value = S.library_result

        result = getattr(self.driver, method)(*args)

        lib_call.assert_called_once_with(*expected_args, **expected_kwargs)
        if returns:
            self.assertEqual(S.library_result, result)
        else:
            self.assertIsNone(result)

    def test_delegation_passes_through_extra_kwargs(self):
        self.library.create_share.return_value = S.library_result

        result = self.driver.create_share(S.context, S.share,
                                          share_server=S.share_server)

        self.library.create_share.assert_called_once_with(
            S.context, S.share, share_server=S.share_server)
        self.assertEqual(S.library_result, result)

    # --------------------------------------------- argument-reshaping methods
    def test_revert_to_snapshot_drops_access_rule_arguments(self):
        """The library reverts the whole volume, so rules are not forwarded."""
        self.library.revert_to_snapshot.return_value = S.library_result

        result = self.driver.revert_to_snapshot(
            S.context, S.snapshot, S.share_access_rules,
            S.snapshot_access_rules, share_server=S.share_server)

        self.library.revert_to_snapshot.assert_called_once_with(
            S.context, S.snapshot, share_server=S.share_server)
        self.assertEqual(S.library_result, result)

    def test_delete_replica_reorders_replica_before_snapshots(self):
        """Driver takes (snapshots, replica), library (replica, snapshots)."""
        result = self.driver.delete_replica(
            S.context, S.replica_list, S.replica_snapshots, S.replica,
            share_server=S.share_server)

        self.library.delete_replica.assert_called_once_with(
            S.context, S.replica_list, S.replica, S.replica_snapshots,
            share_server=S.share_server)
        self.assertIsNone(result)

    def test_update_replicated_snapshot_drops_context(self):
        self.library.update_replicated_snapshot.return_value = S.library_result

        result = self.driver.update_replicated_snapshot(
            S.context, S.replica_list, S.share_replica, S.replica_snapshots,
            S.replica_snapshot, share_server=S.share_server)

        self.library.update_replicated_snapshot.assert_called_once_with(
            S.replica_list, S.share_replica, S.replica_snapshots,
            S.replica_snapshot, share_server=S.share_server)
        self.assertEqual(S.library_result, result)

    def test_revert_to_replicated_snapshot_drops_access_rules(self):
        self.library.revert_to_replicated_snapshot.return_value = (
            S.library_result)

        result = self.driver.revert_to_replicated_snapshot(
            S.context, S.active_replica, S.replica_list,
            S.active_replica_snapshot, S.replica_snapshots,
            S.share_access_rules, S.snapshot_access_rules,
            share_server=S.share_server)

        self.library.revert_to_replicated_snapshot.assert_called_once_with(
            S.context, S.active_replica, S.replica_list,
            S.active_replica_snapshot, S.replica_snapshots,
            share_server=S.share_server)
        self.assertEqual(S.library_result, result)

    def test_setup_server_renames_to_library_setup_server(self):
        self.library.setup_server.return_value = S.library_result

        result = self.driver._setup_server(S.network_info, S.metadata)

        self.library.setup_server.assert_called_once_with(
            S.network_info, S.metadata)
        self.assertEqual(S.library_result, result)

    def test_setup_server_defaults_metadata_to_none(self):
        self.driver._setup_server(S.network_info)

        self.library.setup_server.assert_called_once_with(
            S.network_info, None)

    def test_teardown_server_renames_to_library_teardown_server(self):
        result = self.driver._teardown_server(
            S.server_details, security_services=S.security_services)

        self.library.teardown_server.assert_called_once_with(
            S.server_details, security_services=S.security_services)
        self.assertIsNone(result)

    def test_get_default_filter_function_forwards_pool(self):
        self.library.get_default_filter_function.return_value = (
            S.library_result)

        result = self.driver.get_default_filter_function(pool=S.pool)

        self.library.get_default_filter_function.assert_called_once_with(
            pool=S.pool)
        self.assertEqual(S.library_result, result)

    # -------------------------------------------------------- share stats
    def test_update_share_stats_feeds_library_data_to_base_driver(self):
        self.library.get_share_stats.return_value = S.stats
        mock_super = self.mock_object(driver.ShareDriver,
                                      '_update_share_stats')
        self.mock_object(self.driver, 'get_goodness_function',
                         mock.Mock(return_value=S.goodness))
        self.driver.get_filter_function = S.filter_function

        self.driver._update_share_stats()

        self.library.get_share_stats.assert_called_once_with(
            get_filter_function=S.filter_function,
            goodness_function=S.goodness)
        mock_super.assert_called_once_with(data=S.stats)

    # ------------------------------------------------- share group fallbacks
    def test_create_share_group_snapshot_passes_base_driver_fallback(self):
        self.library.create_group_snapshot.return_value = S.library_result

        result = self.driver.create_share_group_snapshot(
            S.context, S.snap_dict, share_server=S.share_server)

        args = self.library.create_group_snapshot.call_args[0]
        self.assertEqual(S.context, args[0])
        self.assertEqual(S.snap_dict, args[1])
        self.assertEqual(driver.ShareDriver.create_share_group_snapshot,
                         args[2].__func__)
        self.assertEqual(S.share_server, args[3])
        self.assertEqual(S.library_result, result)

    def test_delete_share_group_snapshot_passes_base_driver_fallback(self):
        self.library.delete_group_snapshot.return_value = S.library_result

        result = self.driver.delete_share_group_snapshot(
            S.context, S.snap_dict, share_server=S.share_server)

        args = self.library.delete_group_snapshot.call_args[0]
        self.assertEqual(S.context, args[0])
        self.assertEqual(S.snap_dict, args[1])
        self.assertEqual(driver.ShareDriver.delete_share_group_snapshot,
                         args[2].__func__)
        self.assertEqual(S.share_server, args[3])
        self.assertEqual(S.library_result, result)

    def test_create_share_group_from_snapshot_passes_fallback(self):
        self.library.create_group_from_snapshot.return_value = S.library_result

        result = self.driver.create_share_group_from_share_group_snapshot(
            S.context, S.share_group_dict, S.snapshot_dict,
            share_server=S.share_server)

        args = self.library.create_group_from_snapshot.call_args[0]
        self.assertEqual(S.context, args[0])
        self.assertEqual(S.share_group_dict, args[1])
        self.assertEqual(S.snapshot_dict, args[2])
        self.assertEqual(
            driver.ShareDriver.create_share_group_from_share_group_snapshot,
            args[3].__func__)
        self.assertEqual(S.share_server, args[4])
        self.assertEqual(S.library_result, result)

    # ------------------------------------------- unsupported in single-SVM
    @ddt.data(
        ('manage_existing_with_server', (S.share, S.driver_options)),
        ('unmanage_with_server', (S.share,)),
        ('manage_existing_snapshot_with_server',
         (S.snapshot, S.driver_options)),
        ('unmanage_snapshot_with_server', (S.snapshot,)),
        ('get_share_server_network_info',
         (S.context, S.share_server, S.identifier, S.driver_options)),
        ('manage_server',
         (S.context, S.share_server, S.identifier, S.driver_options)),
        ('unmanage_server', (S.server_details,)),
        ('share_server_migration_start',
         (S.context, S.src_share_server, S.dest_share_server, S.shares,
          S.snapshots)),
        ('share_server_migration_continue',
         (S.context, S.src_share_server, S.dest_share_server, S.shares,
          S.snapshots)),
        ('share_server_migration_complete',
         (S.context, S.src_share_server, S.dest_share_server, S.shares,
          S.snapshots, S.new_network_info)),
        ('share_server_migration_cancel',
         (S.context, S.src_share_server, S.dest_share_server, S.shares,
          S.snapshots)),
        ('share_server_migration_check_compatibility',
         (S.context, S.share_server, S.dest_host, S.old_share_network,
          S.new_share_network, S.shares_request_spec)),
        ('share_server_migration_get_progress',
         (S.context, S.src_share_server, S.dest_share_server)),
        ('choose_share_server_compatible_with_share',
         (S.context, S.share_servers, S.share)),
        ('choose_share_server_compatible_with_share_group',
         (S.context, S.share_servers, S.share_group_ref)),
        ('update_share_server_security_service',
         (S.context, S.share_server, S.network_info, S.share_instances,
          S.share_instance_rules, S.new_security_service)),
        ('check_update_share_server_security_service',
         (S.context, S.share_server, S.network_info, S.share_instances,
          S.share_instance_rules, S.new_security_service)),
        ('check_update_share_server_network_allocations',
         (S.context, S.share_server, S.current_network_allocations,
          S.new_share_network_subnet, S.security_services, S.share_instances,
          S.share_instances_rules)),
        ('update_share_server_network_allocations',
         (S.context, S.share_server, S.current_network_allocations,
          S.new_network_allocations, S.security_services, S.shares,
          S.snapshots)),
        ('update_share_network_subnet_from_metadata',
         (S.context, S.share_network, S.share_network_subnet, S.share_server,
          S.metadata)),
    )
    @ddt.unpack
    def test_share_server_operations_not_implemented(self, method, args):
        """This driver does not handle share servers."""
        self.assertRaises(NotImplementedError,
                          getattr(self.driver, method), *args)
