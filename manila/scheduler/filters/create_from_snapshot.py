# Copyright 2019 NetApp, Inc.
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
from manila.share import utils as share_utils

LOG = log.getLogger(__name__)


class CreateFromSnapshotFilter(base_host.BaseHostFilter):
    """CreateFromSnapshotFilter filters hosts based on replication_domain."""

    def host_passes(self, host_state, filter_properties):
        """Return True if new share's host is compatible with snapshot's host.

        Design of this filter:

            - Creating shares from snapshots in another pool or backend needs
              to match with one of the below conditions:
              - The backend of the new share must be the same as its parent
                snapshot.
              - Both new share and snapshot are in the same replication_domain
        """
        snapshot_id = filter_properties.get('request_spec', {}).get(
            'snapshot_id')
        snapshot_host = filter_properties.get(
            'request_spec', {}).get('snapshot_host')

        if None in [snapshot_id, snapshot_host]:
            # NOTE(silvacarlose): if the request does not contain a snapshot_id
            # or a snapshot_host, the user is not creating a share from a
            # snapshot and we don't need to filter out the host.
            return True

        snapshot_backend = share_utils.extract_host(snapshot_host, 'backend')
        snapshot_rep_domain = filter_properties.get('replication_domain')

        host_backend = share_utils.extract_host(host_state.host, 'backend')
        host_rep_domain = host_state.replication_domain

        # Same backend
        if host_backend == snapshot_backend:
            return True
        # Same replication domain
        if snapshot_rep_domain and snapshot_rep_domain == host_rep_domain:
            return True

        msg = ("The parent's snapshot %(snapshot_id)s back end and "
               "replication domain don't match with the back end and "
               "replication domain of the Host %(host)s.")
        kwargs = {
            "snapshot_id": snapshot_id,
            "host": host_state.host
        }
        LOG.debug(msg, kwargs)
        return False
