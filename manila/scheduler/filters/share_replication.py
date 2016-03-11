# Copyright (c) 2016 Goutham Pacha Ravi
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

from oslo_log import log

from manila.scheduler.filters import base_host

LOG = log.getLogger(__name__)


class ShareReplicationFilter(base_host.BaseHostFilter):
    """ShareReplicationFilter filters hosts based on replication support."""

    def host_passes(self, host_state, filter_properties):
        """Return True if 'active' replica's host can replicate with host.

        Design of this filter:
            - Share replication is symmetric. All backends that can
            replicate between each other must share the same
            'replication_domain'.
            - For scheduling a share that can be replicated in the future,
            this filter checks for 'replication_domain' capability.
            - For scheduling a replica, it checks for the
            'replication_domain' compatibility.
        """
        active_replica_host = filter_properties.get('request_spec', {}).get(
            'active_replica_host')
        existing_replica_hosts = filter_properties.get('request_spec', {}).get(
            'all_replica_hosts', '').split(',')
        replication_type = filter_properties.get('resource_type', {}).get(
            'extra_specs', {}).get('replication_type')
        active_replica_replication_domain = filter_properties.get(
            'replication_domain')
        host_replication_domain = host_state.replication_domain

        if replication_type is None:
            # NOTE(gouthamr): You're probably not creating a replicated
            # share or a replica, then this host obviously passes.
            return True
        elif host_replication_domain is None:
            msg = "Replication is not enabled on host %s."
            LOG.debug(msg, host_state.host)
            return False
        elif active_replica_host is None:
            # 'replication_type' filtering will be handled by the
            # capabilities filter, since it is a share-type extra-spec.
            return True

        # Scheduler filtering by replication_domain for a replica
        if active_replica_replication_domain != host_replication_domain:
            msg = ("The replication domain of Host %(host)s is "
                   "'%(host_domain)s' and it does not match the replication "
                   "domain of the 'active' replica's host: "
                   "%(active_replica_host)s, which is '%(arh_domain)s'. ")
            kwargs = {
                "host": host_state.host,
                "host_domain": host_replication_domain,
                "active_replica_host": active_replica_host,
                "arh_domain": active_replica_replication_domain,
            }
            LOG.debug(msg, kwargs)
            return False

        # Check host string for already created replicas
        if host_state.host in existing_replica_hosts:
            msg = ("Skipping host %s since it already hosts a replica for "
                   "this share.")
            LOG.debug(msg, host_state.host)
            return False

        return True
