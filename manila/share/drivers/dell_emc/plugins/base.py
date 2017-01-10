# Copyright (c) 2014 EMC Corporation.
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
"""EMC Share Driver Base Plugin API """

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class StorageConnection(object):
    """Subclasses should implement storage backend specific functionality."""

    def __init__(self, *args, **kwargs):
        # NOTE(vponomaryov): redefine 'driver_handles_share_servers' within
        #                    plugin.
        self.driver_handles_share_servers = None

    @abc.abstractmethod
    def create_share(self, context, share, share_server):
        """Is called to create share."""

    @abc.abstractmethod
    def create_snapshot(self, context, snapshot, share_server):
        """Is called to create snapshot."""

    @abc.abstractmethod
    def delete_share(self, context, share, share_server):
        """Is called to remove share."""

    @abc.abstractmethod
    def delete_snapshot(self, context, snapshot, share_server):
        """Is called to remove snapshot."""

    @abc.abstractmethod
    def ensure_share(self, context, share, share_server):
        """Invoked to ensure that share is exported."""

    @abc.abstractmethod
    def extend_share(self, share, new_size, share_server):
        """Invoked to extend share."""

    @abc.abstractmethod
    def allow_access(self, context, share, access, share_server):
        """Allow access to the share."""

    @abc.abstractmethod
    def deny_access(self, context, share, access, share_server):
        """Deny access to the share."""

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share."""
        raise NotImplementedError()

    def raise_connect_error(self):
        """Check for setup error."""
        pass

    def connect(self, emc_share_driver, context):
        """Any initialization the share driver does while starting."""
        pass

    def update_share_stats(self, stats_dict):
        """Add key/values to stats_dict."""
        pass

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return 0

    @abc.abstractmethod
    def setup_server(self, network_info, metadata=None):
        """Set up and configure share server with given network parameters."""

    @abc.abstractmethod
    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
