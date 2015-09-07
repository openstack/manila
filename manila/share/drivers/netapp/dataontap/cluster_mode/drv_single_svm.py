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
NetApp Data ONTAP cDOT single-SVM storage driver.

This driver requires a Data ONTAP (Cluster-mode) storage system with
installed CIFS and/or NFS licenses, as well as a FlexClone license.  This
driver does not manage share servers, meaning it uses a single Data ONTAP
storage virtual machine (i.e. 'vserver') as defined in manila.conf to
provision shares.  This driver supports NFS & CIFS protocols.
"""

from manila.share import driver
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_single_svm


class NetAppCmodeSingleSvmShareDriver(driver.ShareDriver):
    """NetApp Cluster-mode single-SVM share driver."""

    DRIVER_NAME = 'NetApp_Cluster_SingleSVM'

    def __init__(self, *args, **kwargs):
        super(NetAppCmodeSingleSvmShareDriver, self).__init__(
            False, *args, **kwargs)
        self.library = lib_single_svm.NetAppCmodeSingleSVMFileStorageLibrary(
            self.DRIVER_NAME, **kwargs)

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
        self.library.create_snapshot(context, snapshot, **kwargs)

    def delete_share(self, context, share, **kwargs):
        self.library.delete_share(context, share, **kwargs)

    def delete_snapshot(self, context, snapshot, **kwargs):
        self.library.delete_snapshot(context, snapshot, **kwargs)

    def extend_share(self, share, new_size, **kwargs):
        self.library.extend_share(share, new_size, **kwargs)

    def shrink_share(self, share, new_size, **kwargs):
        self.library.shrink_share(share, new_size, **kwargs)

    def create_consistency_group(self, context, cg_dict, **kwargs):
        return self.library.create_consistency_group(context, cg_dict,
                                                     **kwargs)

    def create_consistency_group_from_cgsnapshot(self, context, cg_dict,
                                                 cgsnapshot_dict, **kwargs):
        return self.library.create_consistency_group_from_cgsnapshot(
            context, cg_dict, cgsnapshot_dict, **kwargs)

    def delete_consistency_group(self, context, cg_dict, **kwargs):
        return self.library.delete_consistency_group(context, cg_dict,
                                                     **kwargs)

    def create_cgsnapshot(self, context, snap_dict, **kwargs):
        return self.library.create_cgsnapshot(context, snap_dict, **kwargs)

    def delete_cgsnapshot(self, context, snap_dict, **kwargs):
        return self.library.delete_cgsnapshot(context, snap_dict, **kwargs)

    def ensure_share(self, context, share, **kwargs):
        pass

    def manage_existing(self, share, driver_options):
        return self.library.manage_existing(share, driver_options)

    def unmanage(self, share):
        self.library.unmanage(share)

    def allow_access(self, context, share, access, **kwargs):
        self.library.allow_access(context, share, access, **kwargs)

    def deny_access(self, context, share, access, **kwargs):
        self.library.deny_access(context, share, access, **kwargs)

    def _update_share_stats(self, data=None):
        data = self.library.get_share_stats()
        super(NetAppCmodeSingleSvmShareDriver, self)._update_share_stats(
            data=data)

    def get_share_server_pools(self, share_server):
        return self.library.get_share_server_pools(share_server)

    def get_network_allocations_number(self):
        return self.library.get_network_allocations_number()

    def _setup_server(self, network_info, metadata=None):
        return self.library.setup_server(network_info, metadata)

    def _teardown_server(self, server_details, **kwargs):
        self.library.teardown_server(server_details, **kwargs)
