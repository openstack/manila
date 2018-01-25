# Copyright (c) 2015 Huawei Technologies Co., Ltd.
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

"""Abstract base class to work with share."""
import abc

import six


@six.add_metaclass(abc.ABCMeta)
class HuaweiBase(object):
    """Interface to work with share."""

    def __init__(self, configuration):
        """Do initialization."""
        self.configuration = configuration

    @abc.abstractmethod
    def create_share(self, share, share_server):
        """Is called to create share."""

    @abc.abstractmethod
    def create_snapshot(self, snapshot, share_server):
        """Is called to create snapshot."""

    @abc.abstractmethod
    def delete_share(self, share, share_server):
        """Is called to remove share."""

    @abc.abstractmethod
    def delete_snapshot(self, snapshot, share_server):
        """Is called to remove snapshot."""

    @abc.abstractmethod
    def allow_access(self, share, access, share_server):
        """Allow access to the share."""

    @abc.abstractmethod
    def deny_access(self, share, access, share_server):
        """Deny access to the share."""

    @abc.abstractmethod
    def ensure_share(self, share, share_server=None):
        """Ensure that share is exported."""

    @abc.abstractmethod
    def update_access(self, share, access_rules, add_rules,
                      delete_rules, share_server):
        """Update access rules list."""

    @abc.abstractmethod
    def extend_share(self, share, new_size, share_server):
        """Extends size of existing share."""

    @abc.abstractmethod
    def create_share_from_snapshot(self, share, snapshot,
                                   share_server=None):
        """Create share from snapshot."""

    @abc.abstractmethod
    def shrink_share(self, share, new_size, share_server):
        """Shrinks size of existing share."""

    @abc.abstractmethod
    def manage_existing(self, share, driver_options):
        """Manage existing share."""

    @abc.abstractmethod
    def manage_existing_snapshot(self, snapshot, driver_options):
        """Manage existing snapshot."""

    @abc.abstractmethod
    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""

    @abc.abstractmethod
    def get_pool(self, share):
        """Return pool name where the share resides on."""

    def update_share_stats(self, stats_dict):
        """Retrieve stats info from share group."""

    @abc.abstractmethod
    def setup_server(self, network_info, metadata=None):
        """Set up share server with given network parameters."""

    @abc.abstractmethod
    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""

    @abc.abstractmethod
    def create_replica(self, context, replica_list, new_replica,
                       access_rules, replica_snapshots, share_server=None):
        """Replicate the active replica to a new replica on this backend."""

    @abc.abstractmethod
    def update_replica_state(self, context, replica_list, replica,
                             access_rules, replica_snapshots,
                             share_server=None):
        """Update the replica_state of a replica."""

    @abc.abstractmethod
    def promote_replica(self, context, replica_list, replica, access_rules,
                        share_server=None):
        """Promote a replica to 'active' replica state."""

    @abc.abstractmethod
    def delete_replica(self, context, replica_list, replica_snapshots,
                       replica, share_server=None):
        """Delete a replica."""

    @abc.abstractmethod
    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        """Revert a snapshot."""
