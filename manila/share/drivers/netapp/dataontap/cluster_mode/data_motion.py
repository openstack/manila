# Copyright (c) 2016 Alex Meade.  All rights reserved.
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
NetApp Data ONTAP data motion library.

This library handles transferring data from a source to a destination. Its
responsibility is to handle this as efficiently as possible given the
location of the data's source and destination. This includes cloning,
SnapMirror, and copy-offload as improvements to brute force data transfer.
"""

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils

from manila import exception
from manila.i18n import _
from manila.share import configuration
from manila.share import driver
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp import options as na_opts
from manila.share.drivers.netapp import utils as na_utils
from manila.share import utils as share_utils
from manila import utils


LOG = log.getLogger(__name__)
CONF = cfg.CONF


def get_backend_configuration(backend_name):
    config_stanzas = CONF.list_all_sections()
    if backend_name not in config_stanzas:
        msg = _("Could not find backend stanza %(backend_name)s in "
                "configuration which is required for replication or migration "
                "workflows with the source backend. Available stanzas are "
                "%(stanzas)s")
        params = {
            "stanzas": config_stanzas,
            "backend_name": backend_name,
        }
        raise exception.BadConfigurationException(reason=msg % params)

    config = configuration.Configuration(driver.share_opts,
                                         config_group=backend_name)
    config.append_config_values(na_opts.netapp_cluster_opts)
    config.append_config_values(na_opts.netapp_connection_opts)
    config.append_config_values(na_opts.netapp_basicauth_opts)
    config.append_config_values(na_opts.netapp_transport_opts)
    config.append_config_values(na_opts.netapp_support_opts)
    config.append_config_values(na_opts.netapp_provisioning_opts)
    config.append_config_values(na_opts.netapp_data_motion_opts)

    return config


def get_client_for_backend(backend_name, vserver_name=None):
    config = get_backend_configuration(backend_name)
    client = client_cmode.NetAppCmodeClient(
        transport_type=config.netapp_transport_type,
        username=config.netapp_login,
        password=config.netapp_password,
        hostname=config.netapp_server_hostname,
        port=config.netapp_server_port,
        vserver=vserver_name or config.netapp_vserver,
        trace=na_utils.TRACE_API)

    return client


class DataMotionSession(object):

    def _get_backend_volume_name(self, config, share_obj):
        """Return the calculated backend name of the share.

        Uses the netapp_volume_name_template configuration value for the
        backend to calculate the volume name on the array for the share.
        """
        volume_name = config.netapp_volume_name_template % {
            'share_id': share_obj['id'].replace('-', '_')}
        return volume_name

    def _get_backend_qos_policy_group_name(self, share):
        """Get QoS policy name according to QoS policy group name template."""
        __, config = self._get_backend_config_obj(share)
        return config.netapp_qos_policy_group_name_template % {
            'share_id': share['id'].replace('-', '_')}

    def get_vserver_from_share(self, share_obj):
        share_server = share_obj.get('share_server')
        if share_server:
            backend_details = share_server.get('backend_details')
            if backend_details:
                return backend_details.get('vserver_name')

    def _get_backend_config_obj(self, share_obj):
        backend_name = share_utils.extract_host(
            share_obj['host'], level='backend_name')
        config = get_backend_configuration(backend_name)
        return backend_name, config

    def get_backend_info_for_share(self, share_obj):
        backend_name, config = self._get_backend_config_obj(share_obj)
        vserver = (self.get_vserver_from_share(share_obj) or
                   config.netapp_vserver)
        volume_name = self._get_backend_volume_name(
            config, share_obj)

        return volume_name, vserver, backend_name

    def get_snapmirrors(self, source_share_obj, dest_share_obj):
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        snapmirrors = dest_client.get_snapmirrors(
            src_vserver, src_volume_name,
            dest_vserver, dest_volume_name,
            desired_attributes=['relationship-status',
                                'mirror-state',
                                'source-vserver',
                                'source-volume',
                                'last-transfer-end-timestamp'])
        return snapmirrors

    def create_snapmirror(self, source_share_obj, dest_share_obj):
        """Sets up a SnapMirror relationship between two volumes.

        1. Create SnapMirror relationship
        2. Initialize data transfer asynchronously
        """
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        # 1. Create SnapMirror relationship
        # TODO(ameade): Change the schedule from hourly to a config value
        dest_client.create_snapmirror(src_vserver,
                                      src_volume_name,
                                      dest_vserver,
                                      dest_volume_name,
                                      schedule='hourly')

        # 2. Initialize async transfer of the initial data
        dest_client.initialize_snapmirror(src_vserver,
                                          src_volume_name,
                                          dest_vserver,
                                          dest_volume_name)

    def delete_snapmirror(self, source_share_obj, dest_share_obj,
                          release=True):
        """Ensures all information about a SnapMirror relationship is removed.

        1. Abort snapmirror
        2. Delete the snapmirror
        3. Release snapmirror to cleanup snapmirror metadata and snapshots
        """
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, src_backend = (
            self.get_backend_info_for_share(source_share_obj))

        # 1. Abort any ongoing transfers
        try:
            dest_client.abort_snapmirror(src_vserver,
                                         src_volume_name,
                                         dest_vserver,
                                         dest_volume_name,
                                         clear_checkpoint=False)
        except netapp_api.NaApiError as e:
            # Snapmirror is already deleted
            pass

        # 2. Delete SnapMirror Relationship and cleanup destination snapshots
        try:
            dest_client.delete_snapmirror(src_vserver,
                                          src_volume_name,
                                          dest_vserver,
                                          dest_volume_name)
        except netapp_api.NaApiError as e:
            with excutils.save_and_reraise_exception() as exc_context:
                if (e.code == netapp_api.EOBJECTNOTFOUND or
                        e.code == netapp_api.ESOURCE_IS_DIFFERENT or
                        "(entry doesn't exist)" in e.message):
                    LOG.info('No snapmirror relationship to delete')
                    exc_context.reraise = False

        if release:
            # If the source is unreachable, do not perform the release
            try:
                src_client = get_client_for_backend(src_backend,
                                                    vserver_name=src_vserver)
            except Exception:
                src_client = None
            # 3. Cleanup SnapMirror relationship on source
            try:
                if src_client:
                    src_client.release_snapmirror(src_vserver,
                                                  src_volume_name,
                                                  dest_vserver,
                                                  dest_volume_name)
            except netapp_api.NaApiError as e:
                with excutils.save_and_reraise_exception() as exc_context:
                    if (e.code == netapp_api.EOBJECTNOTFOUND or
                            e.code == netapp_api.ESOURCE_IS_DIFFERENT or
                            "(entry doesn't exist)" in e.message):
                        # Handle the case where the snapmirror is already
                        # cleaned up
                        exc_context.reraise = False

    def update_snapmirror(self, source_share_obj, dest_share_obj):
        """Schedule a snapmirror update to happen on the backend."""
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        # Update SnapMirror
        dest_client.update_snapmirror(src_vserver,
                                      src_volume_name,
                                      dest_vserver,
                                      dest_volume_name)

    def quiesce_then_abort(self, source_share_obj, dest_share_obj):
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        # 1. Attempt to quiesce, then abort
        dest_client.quiesce_snapmirror(src_vserver,
                                       src_volume_name,
                                       dest_vserver,
                                       dest_volume_name)

        config = get_backend_configuration(share_utils.extract_host(
            source_share_obj['host'], level='backend_name'))
        retries = config.netapp_snapmirror_quiesce_timeout / 5

        @utils.retry(exception.ReplicationException, interval=5,
                     retries=retries, backoff_rate=1)
        def wait_for_quiesced():
            snapmirror = dest_client.get_snapmirrors(
                src_vserver, src_volume_name, dest_vserver,
                dest_volume_name, desired_attributes=['relationship-status',
                                                      'mirror-state']
            )[0]
            if snapmirror.get('relationship-status') != 'quiesced':
                raise exception.ReplicationException(
                    reason=("Snapmirror relationship is not quiesced."))

        try:
            wait_for_quiesced()
        except exception.ReplicationException:
            dest_client.abort_snapmirror(src_vserver,
                                         src_volume_name,
                                         dest_vserver,
                                         dest_volume_name,
                                         clear_checkpoint=False)

    def break_snapmirror(self, source_share_obj, dest_share_obj, mount=True):
        """Breaks SnapMirror relationship.

        1. Quiesce any ongoing snapmirror transfers
        2. Wait until snapmirror finishes transfers and enters quiesced state
        3. Break snapmirror
        4. Mount the destination volume so it is exported as a share
        """
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        # 1. Attempt to quiesce, then abort
        self.quiesce_then_abort(source_share_obj, dest_share_obj)

        # 2. Break SnapMirror
        dest_client.break_snapmirror(src_vserver,
                                     src_volume_name,
                                     dest_vserver,
                                     dest_volume_name)

        # 3. Mount the destination volume and create a junction path
        if mount:
            dest_client.mount_volume(dest_volume_name)

    def resync_snapmirror(self, source_share_obj, dest_share_obj):
        """Resync SnapMirror relationship. """
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        dest_client.resync_snapmirror(src_vserver,
                                      src_volume_name,
                                      dest_vserver,
                                      dest_volume_name)

    def resume_snapmirror(self, source_share_obj, dest_share_obj):
        """Resume SnapMirror relationship from a quiesced state."""
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        dest_client.resume_snapmirror(src_vserver,
                                      src_volume_name,
                                      dest_vserver,
                                      dest_volume_name)

    def change_snapmirror_source(self, replica,
                                 orig_source_replica,
                                 new_source_replica, replica_list):
        """Creates SnapMirror relationship from the new source to destination.

        1. Delete all snapmirrors involving the replica, but maintain
        snapmirror metadata and snapshots for efficiency
        2. Ensure a new source -> replica snapmirror exists
        3. Resync new source -> replica snapmirror relationship
        """

        replica_volume_name, replica_vserver, replica_backend = (
            self.get_backend_info_for_share(replica))
        replica_client = get_client_for_backend(replica_backend,
                                                vserver_name=replica_vserver)

        new_src_volume_name, new_src_vserver, __ = (
            self.get_backend_info_for_share(new_source_replica))

        # 1. delete
        for other_replica in replica_list:
            if other_replica['id'] == replica['id']:
                continue

            # We need to delete ALL snapmirror relationships
            # involving this replica but do not remove snapmirror metadata
            # so that the new snapmirror relationship is efficient.
            self.delete_snapmirror(other_replica, replica, release=False)
            self.delete_snapmirror(replica, other_replica, release=False)

        # 2. create
        # TODO(ameade): Update the schedule if needed.
        replica_client.create_snapmirror(new_src_vserver,
                                         new_src_volume_name,
                                         replica_vserver,
                                         replica_volume_name,
                                         schedule='hourly')
        # 3. resync
        replica_client.resync_snapmirror(new_src_vserver,
                                         new_src_volume_name,
                                         replica_vserver,
                                         replica_volume_name)

    @na_utils.trace
    def remove_qos_on_old_active_replica(self, orig_active_replica):
        old_active_replica_qos_policy = (
            self._get_backend_qos_policy_group_name(orig_active_replica)
        )
        replica_volume_name, replica_vserver, replica_backend = (
            self.get_backend_info_for_share(orig_active_replica))
        replica_client = get_client_for_backend(
            replica_backend, vserver_name=replica_vserver)
        try:
            replica_client.set_qos_policy_group_for_volume(
                replica_volume_name, 'none')
            replica_client.mark_qos_policy_group_for_deletion(
                old_active_replica_qos_policy)
        except exception.StorageCommunicationException:
            LOG.exception("Could not communicate with the backend "
                          "for replica %s to unset QoS policy and mark "
                          "the QoS policy group for deletion.",
                          orig_active_replica['id'])
