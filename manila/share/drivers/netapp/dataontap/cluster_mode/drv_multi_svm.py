# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
"""
NetApp Data ONTAP cDOT multi-SVM storage driver.

This driver requires a Data ONTAP (Cluster-mode) storage system with
installed CIFS and/or NFS licenses, as well as a FlexClone license.  This
driver manages share servers, meaning it creates Data ONTAP storage virtual
machines (i.e. 'vservers') for each share network for provisioning shares.
This driver supports NFS & CIFS protocols.
"""

from manila.share import driver
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_multi_svm


class NetAppCmodeMultiSvmShareDriver(driver.ShareDriver):
    """NetApp Cluster-mode multi-SVM share driver."""

    DRIVER_NAME = 'NetApp_Cluster_MultiSVM'

    def __init__(self, *args, **kwargs):
        super(NetAppCmodeMultiSvmShareDriver, self).__init__(
            True, *args, **kwargs)
        self.library = lib_multi_svm.NetAppCmodeMultiSVMFileStorageLibrary(
            self.DRIVER_NAME, **kwargs)
        # NetApp driver supports updating security service for in use share
        # networks.
        self.security_service_update_support = True
        self.dhss_mandatory_security_service_association = {
            'nfs': None,
            'cifs': ['active_directory', ]
        }
        # NetApp driver supports multiple subnets including update existing
        # share servers.
        self.network_allocation_update_support = True

    def do_setup(self, context):
        self.library.do_setup(context)

    def check_for_setup_error(self):
        self.library.check_for_setup_error()

    def get_pool(self, share):
        return self.library.get_pool(share)

    def create_share(self, context, share, **kwargs):
        return self.library.create_share(context, share, **kwargs)

    def create_share_from_snapshot(self, context, share, snapshot, **kwargs):
        return self.library.create_share_from_snapshot(context, share,
                                                       snapshot, **kwargs)

    def create_snapshot(self, context, snapshot, **kwargs):
        return self.library.create_snapshot(context, snapshot, **kwargs)

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, **kwargs):
        return self.library.revert_to_snapshot(context, snapshot, **kwargs)

    def delete_share(self, context, share, **kwargs):
        self.library.delete_share(context, share, **kwargs)

    def delete_snapshot(self, context, snapshot, **kwargs):
        self.library.delete_snapshot(context, snapshot, **kwargs)

    def extend_share(self, share, new_size, **kwargs):
        self.library.extend_share(share, new_size, **kwargs)

    def shrink_share(self, share, new_size, **kwargs):
        self.library.shrink_share(share, new_size, **kwargs)

    def manage_existing(self, share, driver_options):
        raise NotImplementedError

    def unmanage(self, share):
        raise NotImplementedError

    def manage_existing_snapshot(self, snapshot, driver_options):
        raise NotImplementedError

    def unmanage_snapshot(self, snapshot):
        raise NotImplementedError

    def manage_existing_with_server(
            self, share, driver_options, share_server=None):
        return self.library.manage_existing(
            share, driver_options, share_server=share_server)

    def unmanage_with_server(self, share, share_server=None):
        self.library.unmanage(share, share_server=share_server)

    def manage_existing_snapshot_with_server(
            self, snapshot, driver_options, share_server=None):
        return self.library.manage_existing_snapshot(
            snapshot, driver_options, share_server=share_server)

    def unmanage_snapshot_with_server(self, snapshot, share_server=None):
        self.library.unmanage_snapshot(snapshot, share_server=share_server)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, **kwargs):
        self.library.update_access(context, share, access_rules, add_rules,
                                   delete_rules, **kwargs)

    def _update_share_stats(self, data=None):
        data = self.library.get_share_stats(
            get_filter_function=self.get_filter_function,
            goodness_function=self.get_goodness_function())
        super(NetAppCmodeMultiSvmShareDriver, self)._update_share_stats(
            data=data)

    def get_default_filter_function(self, pool=None):
        return self.library.get_default_filter_function(pool=pool)

    def get_default_goodness_function(self):
        return self.library.get_default_goodness_function()

    def get_share_server_pools(self, share_server):
        return self.library.get_share_server_pools(share_server)

    def get_network_allocations_number(self):
        return self.library.get_network_allocations_number()

    def get_admin_network_allocations_number(self):
        return self.library.get_admin_network_allocations_number(
            self.admin_network_api)

    def _setup_server(self, network_info, metadata=None):
        return self.library.setup_server(network_info, metadata)

    def _teardown_server(self, server_details, **kwargs):
        self.library.teardown_server(server_details, **kwargs)

    def create_replica(self, context, replica_list, new_replica, access_rules,
                       replica_snapshots, **kwargs):
        return self.library.create_replica(context, replica_list, new_replica,
                                           access_rules, replica_snapshots)

    def delete_replica(self, context, replica_list, replica_snapshots,
                       replica, **kwargs):
        self.library.delete_replica(context, replica_list, replica,
                                    replica_snapshots)

    def promote_replica(self, context, replica_list, replica, access_rules,
                        share_server=None, quiesce_wait_time=None):
        return self.library.promote_replica(
            context, replica_list, replica,
            access_rules,
            share_server=share_server,
            quiesce_wait_time=quiesce_wait_time)

    def update_replica_state(self, context, replica_list, replica,
                             access_rules, replica_snapshots,
                             share_server=None):
        return self.library.update_replica_state(context, replica_list,
                                                 replica, access_rules,
                                                 replica_snapshots,
                                                 share_server)

    def create_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots, share_server=None):
        return self.library.create_replicated_snapshot(
            context, replica_list, replica_snapshots,
            share_server=share_server)

    def delete_replicated_snapshot(self, context, replica_list,
                                   replica_snapshots, share_server=None):
        return self.library.delete_replicated_snapshot(
            context, replica_list, replica_snapshots,
            share_server=share_server)

    def update_replicated_snapshot(self, context, replica_list,
                                   share_replica, replica_snapshots,
                                   replica_snapshot, share_server=None):
        return self.library.update_replicated_snapshot(
            replica_list, share_replica, replica_snapshots, replica_snapshot,
            share_server=share_server)

    def revert_to_replicated_snapshot(self, context, active_replica,
                                      replica_list, active_replica_snapshot,
                                      replica_snapshots, share_access_rules,
                                      snapshot_access_rules,
                                      **kwargs):
        return self.library.revert_to_replicated_snapshot(
            context, active_replica, replica_list, active_replica_snapshot,
            replica_snapshots, **kwargs)

    def migration_check_compatibility(self, context, source_share,
                                      destination_share, share_server=None,
                                      destination_share_server=None):
        return self.library.migration_check_compatibility(
            context, source_share, destination_share,
            share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_start(self, context, source_share, destination_share,
                        source_snapshots, snapshot_mappings,
                        share_server=None, destination_share_server=None):
        return self.library.migration_start(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings,
            share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_continue(self, context, source_share, destination_share,
                           source_snapshots, snapshot_mappings,
                           share_server=None, destination_share_server=None):
        return self.library.migration_continue(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings, share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_get_progress(self, context, source_share,
                               destination_share, source_snapshots,
                               snapshot_mappings, share_server=None,
                               destination_share_server=None):
        return self.library.migration_get_progress(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings, share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_cancel(self, context, source_share, destination_share,
                         source_snapshots, snapshot_mappings,
                         share_server=None, destination_share_server=None):
        return self.library.migration_cancel(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings, share_server=share_server,
            destination_share_server=destination_share_server)

    def migration_complete(self, context, source_share, destination_share,
                           source_snapshots, snapshot_mappings,
                           share_server=None, destination_share_server=None):
        return self.library.migration_complete(
            context, source_share, destination_share,
            source_snapshots, snapshot_mappings, share_server=share_server,
            destination_share_server=destination_share_server)

    def create_share_group_snapshot(self, context, snap_dict,
                                    share_server=None):
        fallback_create = super(NetAppCmodeMultiSvmShareDriver,
                                self).create_share_group_snapshot
        return self.library.create_group_snapshot(context, snap_dict,
                                                  fallback_create,
                                                  share_server)

    def delete_share_group_snapshot(self, context, snap_dict,
                                    share_server=None):
        fallback_delete = super(NetAppCmodeMultiSvmShareDriver,
                                self).delete_share_group_snapshot
        return self.library.delete_group_snapshot(context, snap_dict,
                                                  fallback_delete,
                                                  share_server)

    def create_share_group_from_share_group_snapshot(
            self, context, share_group_dict, snapshot_dict,
            share_server=None):
        fallback_create = super(
            NetAppCmodeMultiSvmShareDriver,
            self).create_share_group_from_share_group_snapshot
        return self.library.create_group_from_snapshot(context,
                                                       share_group_dict,
                                                       snapshot_dict,
                                                       fallback_create,
                                                       share_server)

    def get_configured_ip_versions(self):
        return self.library.get_configured_ip_versions()

    def get_backend_info(self, context):
        return self.library.get_backend_info(context)

    def ensure_shares(self, context, shares):
        return self.library.ensure_shares(context, shares)

    def get_share_server_network_info(
            self, context, share_server, identifier, driver_options):
        return self.library.get_share_server_network_info(
            context, share_server, identifier, driver_options)

    def manage_server(self, context, share_server, identifier, driver_options):
        return self.library.manage_server(
            context, share_server, identifier, driver_options)

    def unmanage_server(self, server_details, security_services=None):
        return self.library.unmanage_server(server_details, security_services)

    def get_share_status(self, share_instance, share_server=None):
        return self.library.get_share_status(share_instance, share_server)

    def share_server_migration_check_compatibility(
            self, context, share_server, dest_host, old_share_network,
            new_share_network, shares_request_spec):

        return self.library.share_server_migration_check_compatibility(
            context, share_server, dest_host, old_share_network,
            new_share_network, shares_request_spec)

    def share_server_migration_start(self, context, src_share_server,
                                     dest_share_server, shares, snapshots):
        return self.library.share_server_migration_start(
            context, src_share_server, dest_share_server, shares, snapshots)

    def share_server_migration_continue(self, context, src_share_server,
                                        dest_share_server, shares, snapshots):
        return self.library.share_server_migration_continue(
            context, src_share_server, dest_share_server, shares, snapshots)

    def share_server_migration_complete(self, context, src_share_server,
                                        dest_share_server, shares, snapshots,
                                        new_network_info):
        return self.library.share_server_migration_complete(
            context, src_share_server, dest_share_server, shares, snapshots,
            new_network_info)

    def share_server_migration_cancel(self, context, src_share_server,
                                      dest_share_server, shares, snapshots):
        self.library.share_server_migration_cancel(
            context, src_share_server, dest_share_server, shares, snapshots)

    def choose_share_server_compatible_with_share(self, context, share_servers,
                                                  share, snapshot=None,
                                                  share_group=None):
        return self.library.choose_share_server_compatible_with_share(
            context, share_servers, share, snapshot=snapshot,
            share_group=share_group)

    def choose_share_server_compatible_with_share_group(
            self, context, share_servers, share_group_ref,
            share_group_snapshot=None):
        return self.library.choose_share_server_compatible_with_share_group(
            context, share_servers, share_group_ref,
            share_group_snapshot=share_group_snapshot)

    def share_server_migration_get_progress(self, context, src_share_server,
                                            dest_share_server, shares,
                                            snapshots):
        return self.library.share_server_migration_get_progress(
            context, src_share_server, dest_share_server, shares, snapshots)

    def update_share_server_security_service(
            self, context, share_server, network_info, share_instances,
            share_instance_rules, new_security_service,
            current_security_service=None):
        return self.library.update_share_server_security_service(
            context, share_server, network_info, new_security_service,
            current_security_service=current_security_service)

    def check_update_share_server_security_service(
            self, context, share_server, network_info, share_instances,
            share_instance_rules, new_security_service,
            current_security_service=None):
        return self.library.check_update_share_server_security_service(
            context, share_server, network_info, new_security_service,
            current_security_service=current_security_service)

    def check_update_share_server_network_allocations(
            self, context, share_server, current_network_allocations,
            new_share_network_subnet, security_services, share_instances,
            share_instances_rules):
        return self.library.check_update_share_server_network_allocations(
            context, share_server, current_network_allocations,
            new_share_network_subnet, security_services, share_instances,
            share_instances_rules)

    def update_share_server_network_allocations(
            self, context, share_server, current_network_allocations,
            new_network_allocations, security_services, shares, snapshots):
        return self.library.update_share_server_network_allocations(
            context, share_server, current_network_allocations,
            new_network_allocations, security_services, shares, snapshots)
