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
from manila.share.drivers.netapp.dataontap.client import client_cmode_rest
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
    if config.driver_handles_share_servers:
        # NOTE(dviroel): avoid using a pre-create vserver on DHSS == True mode
        # when retrieving remote backend configuration.
        config.netapp_vserver = None
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
    if config.netapp_use_legacy_client:
        client = client_cmode.NetAppCmodeClient(
            transport_type=config.netapp_transport_type,
            ssl_cert_path=config.netapp_ssl_cert_path,
            username=config.netapp_login,
            password=config.netapp_password,
            hostname=config.netapp_server_hostname,
            port=config.netapp_server_port,
            vserver=vserver_name or config.netapp_vserver,
            trace=na_utils.TRACE_API)
    else:
        client = client_cmode_rest.NetAppRestClient(
            transport_type=config.netapp_transport_type,
            ssl_cert_path=config.netapp_ssl_cert_path,
            username=config.netapp_login,
            password=config.netapp_password,
            hostname=config.netapp_server_hostname,
            port=config.netapp_server_port,
            vserver=vserver_name or config.netapp_vserver,
            async_rest_timeout=config.netapp_rest_operation_timeout,
            trace=na_utils.TRACE_API)

    return client


def get_client_for_host(host):
    """Returns a cluster client to the desired host."""
    backend_name = share_utils.extract_host(host, level='backend_name')
    client = get_client_for_backend(backend_name)
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
        __, config = self.get_backend_name_and_config_obj(share['host'])
        return config.netapp_qos_policy_group_name_template % {
            'share_id': share['id'].replace('-', '_')}

    def _get_backend_snapmirror_policy_name_svm(self, share_server_id,
                                                backend_name):
        config = get_backend_configuration(backend_name)
        return (config.netapp_snapmirror_policy_name_svm_template
                % {'share_server_id': share_server_id.replace('-', '_')})

    def get_vserver_from_share_server(self, share_server):
        backend_details = share_server.get('backend_details')
        if backend_details:
            return backend_details.get('vserver_name')

    def get_vserver_from_share(self, share_obj):
        share_server = share_obj.get('share_server')
        if share_server:
            return self.get_vserver_from_share_server(share_server)

    def get_backend_name_and_config_obj(self, host):
        backend_name = share_utils.extract_host(host, level='backend_name')
        config = get_backend_configuration(backend_name)
        return backend_name, config

    def get_backend_info_for_share(self, share_obj):
        backend_name, config = self.get_backend_name_and_config_obj(
            share_obj['host'])
        vserver = (self.get_vserver_from_share(share_obj) or
                   config.netapp_vserver)
        volume_name = self._get_backend_volume_name(config, share_obj)

        return volume_name, vserver, backend_name

    def get_client_and_vserver_name(self, share_server):
        destination_host = share_server.get('host')
        vserver = self.get_vserver_from_share_server(share_server)
        backend, __ = self.get_backend_name_and_config_obj(destination_host)
        client = get_client_for_backend(backend, vserver_name=vserver)

        return client, vserver

    def get_snapmirrors(self, source_share_obj, dest_share_obj):
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        snapmirrors = dest_client.get_snapmirrors(
            source_vserver=src_vserver, dest_vserver=dest_vserver,
            source_volume=src_volume_name, dest_volume=dest_volume_name,
            desired_attributes=['relationship-status',
                                'mirror-state',
                                'schedule',
                                'source-vserver',
                                'source-volume',
                                'last-transfer-end-timestamp',
                                'last-transfer-size',
                                'last-transfer-error'])
        return snapmirrors

    def create_snapmirror(self, source_share_obj, dest_share_obj,
                          relationship_type, mount=False):
        """Sets up a SnapMirror relationship between two volumes.

        1. Create SnapMirror relationship.
        2. Initialize data transfer asynchronously.
        3. Mount destination volume if requested.
        """
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        # 1. Create SnapMirror relationship
        config = get_backend_configuration(dest_backend)
        schedule = config.netapp_snapmirror_schedule
        dest_client.create_snapmirror_vol(src_vserver,
                                          src_volume_name,
                                          dest_vserver,
                                          dest_volume_name,
                                          relationship_type,
                                          schedule=schedule)

        # 2. Initialize async transfer of the initial data
        dest_client.initialize_snapmirror_vol(src_vserver,
                                              src_volume_name,
                                              dest_vserver,
                                              dest_volume_name)

        # 3. Mount the destination volume and create a junction path
        if mount:
            replica_config = get_backend_configuration(dest_backend)
            self.wait_for_mount_replica(
                dest_client, dest_volume_name,
                timeout=replica_config.netapp_mount_replica_timeout)

    def delete_snapmirror(self, source_share_obj, dest_share_obj,
                          release=True, relationship_info_only=False):
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
            dest_client.abort_snapmirror_vol(src_vserver,
                                             src_volume_name,
                                             dest_vserver,
                                             dest_volume_name,
                                             clear_checkpoint=False)
        except netapp_api.NaApiError:
            # Snapmirror is already deleted
            pass

        # 2. Delete SnapMirror Relationship and cleanup destination snapshots
        try:
            dest_client.delete_snapmirror_vol(src_vserver,
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
            if src_client:
                src_config = get_backend_configuration(src_backend)
                release_timeout = (
                    src_config.netapp_snapmirror_release_timeout)
                self.wait_for_snapmirror_release_vol(
                    src_vserver, dest_vserver, src_volume_name,
                    dest_volume_name, relationship_info_only, src_client,
                    timeout=release_timeout)

    def update_snapmirror(self, source_share_obj, dest_share_obj):
        """Schedule a snapmirror update to happen on the backend."""
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        # Update SnapMirror
        dest_client.update_snapmirror_vol(src_vserver,
                                          src_volume_name,
                                          dest_vserver,
                                          dest_volume_name)

    def quiesce_then_abort_svm(self, source_share_server, dest_share_server):
        source_client, source_vserver = self.get_client_and_vserver_name(
            source_share_server)
        dest_client, dest_vserver = self.get_client_and_vserver_name(
            dest_share_server)

        # 1. Attempt to quiesce, then abort
        dest_client.quiesce_snapmirror_svm(source_vserver, dest_vserver)

        dest_backend = share_utils.extract_host(dest_share_server['host'],
                                                level='backend_name')
        config = get_backend_configuration(dest_backend)
        retries = config.netapp_snapmirror_quiesce_timeout / 5

        @utils.retry(retry_param=exception.ReplicationException,
                     interval=5,
                     retries=retries,
                     backoff_rate=1)
        def wait_for_quiesced():
            snapmirror = dest_client.get_snapmirrors_svm(
                source_vserver=source_vserver, dest_vserver=dest_vserver,
                desired_attributes=['relationship-status', 'mirror-state']
            )[0]
            if snapmirror.get('relationship-status') not in ['quiesced',
                                                             'paused']:
                raise exception.ReplicationException(
                    reason="Snapmirror relationship is not quiesced.")

        try:
            wait_for_quiesced()
        except exception.ReplicationException:
            dest_client.abort_snapmirror_svm(source_vserver,
                                             dest_vserver,
                                             clear_checkpoint=False)

    def quiesce_then_abort(self, source_share_obj, dest_share_obj,
                           quiesce_wait_time=None):
        dest_volume, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        # 1. Attempt to quiesce, then abort
        dest_client.quiesce_snapmirror_vol(src_vserver,
                                           src_volume,
                                           dest_vserver,
                                           dest_volume)

        config = get_backend_configuration(dest_backend)
        timeout = (
            quiesce_wait_time or config.netapp_snapmirror_quiesce_timeout)
        retries = int(timeout / 5) or 1

        @utils.retry(retry_param=exception.ReplicationException,
                     interval=5,
                     retries=retries,
                     backoff_rate=1)
        def wait_for_quiesced():
            snapmirror = dest_client.get_snapmirrors(
                source_vserver=src_vserver, dest_vserver=dest_vserver,
                source_volume=src_volume, dest_volume=dest_volume,
                desired_attributes=['relationship-status', 'mirror-state']
            )[0]
            if snapmirror.get('relationship-status') not in ['quiesced',
                                                             'paused']:
                raise exception.ReplicationException(
                    reason="Snapmirror relationship is not quiesced.")

        try:
            wait_for_quiesced()
        except exception.ReplicationException:
            dest_client.abort_snapmirror_vol(src_vserver,
                                             src_volume,
                                             dest_vserver,
                                             dest_volume,
                                             clear_checkpoint=False)

    def break_snapmirror(self, source_share_obj, dest_share_obj, mount=True,
                         quiesce_wait_time=None):
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
        self.quiesce_then_abort(source_share_obj, dest_share_obj,
                                quiesce_wait_time=quiesce_wait_time)

        # 2. Break SnapMirror
        dest_client.break_snapmirror_vol(src_vserver,
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

        dest_client.resync_snapmirror_vol(src_vserver,
                                          src_volume_name,
                                          dest_vserver,
                                          dest_volume_name)

    def modify_snapmirror(self, source_share_obj, dest_share_obj,
                          schedule=None):
        """Modify SnapMirror relationship: set schedule"""
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        if schedule is None:
            config = get_backend_configuration(dest_backend)
            schedule = config.netapp_snapmirror_schedule

        dest_client.modify_snapmirror_vol(src_vserver,
                                          src_volume_name,
                                          dest_vserver,
                                          dest_volume_name,
                                          schedule=schedule)

    def resume_snapmirror(self, source_share_obj, dest_share_obj):
        """Resume SnapMirror relationship from a quiesced state."""
        dest_volume_name, dest_vserver, dest_backend = (
            self.get_backend_info_for_share(dest_share_obj))
        dest_client = get_client_for_backend(dest_backend,
                                             vserver_name=dest_vserver)

        src_volume_name, src_vserver, __ = self.get_backend_info_for_share(
            source_share_obj)

        dest_client.resume_snapmirror_vol(src_vserver,
                                          src_volume_name,
                                          dest_vserver,
                                          dest_volume_name)

    def change_snapmirror_source(self, replica,
                                 orig_source_replica,
                                 new_source_replica, replica_list,
                                 is_flexgroup=False):
        """Creates SnapMirror relationship from the new source to destination.

        1. Delete all snapmirrors involving the replica, but maintain
        snapmirror metadata and snapshots for efficiency
        2. For DHSS=True scenarios, creates a new vserver peer relationship if
        it does not exists
        3. Ensure a new source -> replica snapmirror exists
        4. Resync new source -> replica snapmirror relationship
        """

        replica_volume_name, replica_vserver, replica_backend = (
            self.get_backend_info_for_share(replica))
        replica_client = get_client_for_backend(replica_backend,
                                                vserver_name=replica_vserver)

        new_src_volume_name, new_src_vserver, new_src_backend = (
            self.get_backend_info_for_share(new_source_replica))

        # 1. delete
        for other_replica in replica_list:
            if other_replica['id'] == replica['id']:
                continue

            # deletes all snapmirror relationships involving this replica to
            # ensure new relation can be set. For efficient snapmirror, it
            # does not remove the snapshots, only releasing the relationship
            # info if FlexGroup volume.
            self.delete_snapmirror(other_replica, replica,
                                   release=is_flexgroup,
                                   relationship_info_only=is_flexgroup)
            self.delete_snapmirror(replica, other_replica,
                                   release=is_flexgroup,
                                   relationship_info_only=is_flexgroup)

        # 2. vserver operations when driver handles share servers
        replica_config = get_backend_configuration(replica_backend)
        if (replica_config.driver_handles_share_servers
                and replica_vserver != new_src_vserver):
            # create vserver peering if does not exists
            if not replica_client.get_vserver_peers(replica_vserver,
                                                    new_src_vserver):
                new_src_client = get_client_for_backend(
                    new_src_backend, vserver_name=new_src_vserver)
                # Cluster name is needed for setting up the vserver peering
                new_src_cluster_name = new_src_client.get_cluster_name()
                replica_cluster_name = replica_client.get_cluster_name()

                replica_client.create_vserver_peer(
                    replica_vserver, new_src_vserver,
                    peer_cluster_name=new_src_cluster_name)
                if new_src_cluster_name != replica_cluster_name:
                    new_src_client.accept_vserver_peer(new_src_vserver,
                                                       replica_vserver)

        # 3. create
        relationship_type = na_utils.get_relationship_type(is_flexgroup)
        schedule = replica_config.netapp_snapmirror_schedule
        replica_client.create_snapmirror_vol(new_src_vserver,
                                             new_src_volume_name,
                                             replica_vserver,
                                             replica_volume_name,
                                             relationship_type,
                                             schedule=schedule)

        # 4. resync
        replica_client.resync_snapmirror_vol(new_src_vserver,
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

    def create_snapmirror_svm(self, source_share_server,
                              dest_share_server):
        """Sets up a SnapMirror relationship between two vServers.

        1. Create a SnapMirror policy for SVM DR
        2. Create SnapMirror relationship
        3. Initialize data transfer asynchronously
        """
        dest_client, dest_vserver = self.get_client_and_vserver_name(
            dest_share_server)
        src_vserver = self.get_vserver_from_share_server(source_share_server)

        # 1: Create SnapMirror policy for SVM DR
        dest_backend_name = share_utils.extract_host(dest_share_server['host'],
                                                     level='backend_name')
        policy_name = self._get_backend_snapmirror_policy_name_svm(
            dest_share_server['id'],
            dest_backend_name,
        )
        dest_client.create_snapmirror_policy(policy_name)

        # 2. Create SnapMirror relationship
        dest_client.create_snapmirror_svm(src_vserver,
                                          dest_vserver,
                                          policy=policy_name,
                                          schedule='hourly')

        # 2. Initialize async transfer of the initial data
        dest_client.initialize_snapmirror_svm(src_vserver,
                                              dest_vserver)

    def get_snapmirrors_svm(self, source_share_server, dest_share_server):
        """Get SnapMirrors between two vServers."""

        dest_client, dest_vserver = self.get_client_and_vserver_name(
            dest_share_server)
        src_vserver = self.get_vserver_from_share_server(source_share_server)

        snapmirrors = dest_client.get_snapmirrors_svm(
            source_vserver=src_vserver, dest_vserver=dest_vserver,
            desired_attributes=['relationship-status',
                                'mirror-state',
                                'last-transfer-end-timestamp'])
        return snapmirrors

    def get_snapmirror_destinations_svm(self, source_share_server,
                                        dest_share_server):
        """Get SnapMirrors between two vServers."""

        dest_client, dest_vserver = self.get_client_and_vserver_name(
            dest_share_server)
        src_vserver = self.get_vserver_from_share_server(source_share_server)

        snapmirrors = dest_client.get_snapmirror_destinations_svm(
            source_vserver=src_vserver, dest_vserver=dest_vserver)
        return snapmirrors

    def update_snapmirror_svm(self, source_share_server, dest_share_server):
        """Schedule a SnapMirror update to happen on the backend."""

        dest_client, dest_vserver = self.get_client_and_vserver_name(
            dest_share_server)
        src_vserver = self.get_vserver_from_share_server(source_share_server)

        # Update SnapMirror
        dest_client.update_snapmirror_svm(src_vserver, dest_vserver)

    def quiesce_and_break_snapmirror_svm(self, source_share_server,
                                         dest_share_server):
        """Abort and break a SnapMirror relationship between vServers.

        1. Quiesce SnapMirror
        2. Break SnapMirror
        """
        dest_client, dest_vserver = self.get_client_and_vserver_name(
            dest_share_server)
        src_vserver = self.get_vserver_from_share_server(source_share_server)

        # 1. Attempt to quiesce, then abort
        self.quiesce_then_abort_svm(source_share_server, dest_share_server)

        # 2. Break SnapMirror
        dest_client.break_snapmirror_svm(src_vserver, dest_vserver)

    def cancel_snapmirror_svm(self, source_share_server, dest_share_server):
        """Cancels SnapMirror relationship between vServers."""

        dest_backend = share_utils.extract_host(dest_share_server['host'],
                                                level='backend_name')
        dest_config = get_backend_configuration(dest_backend)
        server_timeout = (
            dest_config.netapp_server_migration_state_change_timeout)
        dest_client, dest_vserver = self.get_client_and_vserver_name(
            dest_share_server)

        snapmirrors = self.get_snapmirrors_svm(source_share_server,
                                               dest_share_server)
        if snapmirrors:
            # 1. Attempt to quiesce and break snapmirror
            self.quiesce_and_break_snapmirror_svm(source_share_server,
                                                  dest_share_server)

            # NOTE(dviroel): Lets wait until the destination vserver be
            # promoted to 'default' and state 'running', before starting
            # shutting down the source
            self.wait_for_vserver_state(dest_vserver, dest_client,
                                        subtype='default', state='running',
                                        operational_state='stopped',
                                        timeout=server_timeout)
            # 2. Delete SnapMirror
            self.delete_snapmirror_svm(source_share_server, dest_share_server)
        else:
            dest_info = dest_client.get_vserver_info(dest_vserver)
            if dest_info is None:
                # NOTE(dviroel): Nothing to cancel since the destination does
                # not exist.
                return
            if dest_info.get('subtype') == 'dp_destination':
                # NOTE(dviroel): Can be a corner case where no snapmirror
                # relationship was found but the destination vserver is stuck
                # in DP mode. We need to convert it to 'default' to release
                # its resources later.
                self.convert_svm_to_default_subtype(dest_vserver, dest_client,
                                                    timeout=server_timeout)

    def convert_svm_to_default_subtype(self, vserver_name, client,
                                       is_dest_path=True, timeout=300):
        interval = 10
        retries = (timeout / interval or 1)

        @utils.retry(retry_param=exception.VserverNotReady,
                     interval=interval,
                     retries=retries,
                     backoff_rate=1)
        def wait_for_state():
            vserver_info = client.get_vserver_info(vserver_name)
            if vserver_info.get('subtype') != 'default':
                if is_dest_path:
                    client.break_snapmirror_svm(dest_vserver=vserver_name)
                else:
                    client.break_snapmirror_svm(source_vserver=vserver_name)
                raise exception.VserverNotReady(vserver=vserver_name)
        try:
            wait_for_state()
        except exception.VserverNotReady:
            msg = _("Vserver %s did not reach the expected state. Retries "
                    "exhausted. Aborting.") % vserver_name
            raise exception.NetAppException(message=msg)

    def delete_snapmirror_svm(self, src_share_server, dest_share_server,
                              release=True):
        """Ensures all information about a SnapMirror relationship is removed.

        1. Abort SnapMirror
        2. Delete the SnapMirror
        3. Release SnapMirror to cleanup SnapMirror metadata and snapshots
        """
        src_client, src_vserver = self.get_client_and_vserver_name(
            src_share_server)
        dest_client, dest_vserver = self.get_client_and_vserver_name(
            dest_share_server)
        # 1. Abort any ongoing transfers
        try:
            dest_client.abort_snapmirror_svm(src_vserver, dest_vserver)
        except netapp_api.NaApiError:
            # SnapMirror is already deleted
            pass

        # 2. Delete SnapMirror Relationship and cleanup destination snapshots
        try:
            dest_client.delete_snapmirror_svm(src_vserver, dest_vserver)
        except netapp_api.NaApiError as e:
            with excutils.save_and_reraise_exception() as exc_context:
                if (e.code == netapp_api.EOBJECTNOTFOUND or
                        e.code == netapp_api.ESOURCE_IS_DIFFERENT or
                        "(entry doesn't exist)" in e.message):
                    LOG.info('No snapmirror relationship to delete')
                    exc_context.reraise = False

        # 3. Release SnapMirror
        if release:
            src_backend = share_utils.extract_host(src_share_server['host'],
                                                   level='backend_name')
            src_config = get_backend_configuration(src_backend)
            release_timeout = (
                src_config.netapp_snapmirror_release_timeout)
            self.wait_for_snapmirror_release_svm(src_vserver,
                                                 dest_vserver,
                                                 src_client,
                                                 timeout=release_timeout)

    def wait_for_vserver_state(self, vserver_name, client, state=None,
                               operational_state=None, subtype=None,
                               timeout=300):
        interval = 10
        retries = (timeout / interval or 1)

        expected = {}
        if state:
            expected['state'] = state
        if operational_state:
            expected['operational_state'] = operational_state
        if subtype:
            expected['subtype'] = subtype

        @utils.retry(retry_param=exception.VserverNotReady,
                     interval=interval,
                     retries=retries,
                     backoff_rate=1)
        def wait_for_state():
            vserver_info = client.get_vserver_info(vserver_name)
            if not all(item in vserver_info.items() for
                       item in expected.items()):
                raise exception.VserverNotReady(vserver=vserver_name)
        try:
            wait_for_state()
        except exception.VserverNotReady:
            msg = _("Vserver %s did not reach the expected state. Retries "
                    "exhausted. Aborting.") % vserver_name
            raise exception.NetAppException(message=msg)

    def wait_for_snapmirror_release_svm(self, source_vserver, dest_vserver,
                                        src_client, timeout=300):
        interval = 10
        retries = (timeout / interval or 1)

        @utils.retry(retry_param=exception.NetAppException,
                     interval=interval,
                     retries=retries,
                     backoff_rate=1)
        def release_snapmirror():
            snapmirrors = src_client.get_snapmirror_destinations_svm(
                source_vserver=source_vserver, dest_vserver=dest_vserver)
            if not snapmirrors:
                LOG.debug("No snapmirrors to be released in source location.")
            else:
                try:
                    src_client.release_snapmirror_svm(source_vserver,
                                                      dest_vserver)
                except netapp_api.NaApiError as e:
                    if (e.code == netapp_api.EOBJECTNOTFOUND or
                            e.code == netapp_api.ESOURCE_IS_DIFFERENT or
                            "(entry doesn't exist)" in e.message):
                        LOG.debug('Snapmirror relationship does not exists '
                                  'anymore.')

                msg = _('Snapmirror release sent to source vserver. We will '
                        'wait for it to be released.')
                raise exception.NetAppException(vserver=msg)

        try:
            release_snapmirror()
        except exception.NetAppException:
            msg = _("Unable to release the snapmirror from source vserver %s. "
                    "Retries exhausted. Aborting") % source_vserver
            raise exception.NetAppException(message=msg)

    def wait_for_mount_replica(self, vserver_client, share_name, timeout=300):
        """Mount a replica share that is waiting for snapmirror initialize."""

        interval = 10
        retries = (timeout // interval or 1)

        @utils.retry(exception.ShareBusyException, interval=interval,
                     retries=retries, backoff_rate=1)
        def try_mount_volume():
            try:
                vserver_client.mount_volume(share_name)
            except netapp_api.NaApiError as e:
                undergoing_snap_init = 'snapmirror initialize'
                msg_args = {'name': share_name}
                if (e.code == netapp_api.EAPIERROR and
                        undergoing_snap_init in e.message):
                    msg = _('The share %(name)s is undergoing a snapmirror '
                            'initialize. Will retry the operation.') % msg_args
                    LOG.warning(msg)
                    raise exception.ShareBusyException(reason=msg)
                else:
                    msg = _("Unable to perform mount operation for the share "
                            "%(name)s. Caught an unexpected error. Not "
                            "retrying.") % msg_args
                    raise exception.NetAppException(message=msg)

        try:
            try_mount_volume()
        except exception.ShareBusyException:
            msg_args = {'name': share_name}
            msg = _("Unable to perform mount operation for the share %(name)s "
                    "because a snapmirror initialize operation is still in "
                    "progress. Retries exhausted. Not retrying.") % msg_args
            raise exception.NetAppException(message=msg)

    def wait_for_snapmirror_release_vol(self, src_vserver, dest_vserver,
                                        src_volume_name, dest_volume_name,
                                        relationship_info_only, src_client,
                                        timeout=300):
        interval = 10
        retries = (timeout / interval or 1)

        @utils.retry(exception.NetAppException, interval=interval,
                     retries=retries, backoff_rate=1)
        def release_snapmirror():
            snapmirrors = src_client.get_snapmirror_destinations(
                source_vserver=src_vserver, dest_vserver=dest_vserver,
                source_volume=src_volume_name, dest_volume=dest_volume_name)
            if not snapmirrors:
                LOG.debug("No snapmirrors to be released in source volume.")
            else:
                try:
                    src_client.release_snapmirror_vol(
                        src_vserver, src_volume_name, dest_vserver,
                        dest_volume_name,
                        relationship_info_only=relationship_info_only)
                except netapp_api.NaApiError as e:
                    if (e.code == netapp_api.EOBJECTNOTFOUND or
                            e.code == netapp_api.ESOURCE_IS_DIFFERENT or
                            "(entry doesn't exist)" in e.message):
                        LOG.debug('Snapmirror relationship does not exist '
                                  'anymore.')

                msg = _('Snapmirror release sent to source volume. Waiting '
                        'until it has been released.')
                raise exception.NetAppException(vserver=msg)

        try:
            release_snapmirror()
        except exception.NetAppException:
            msg = _("Unable to release the snapmirror from source volume %s. "
                    "Retries exhausted. Aborting") % src_volume_name
            raise exception.NetAppException(message=msg)

    def cleanup_previous_snapmirror_relationships(self, replica, replica_list):
        """Cleanup previous snapmirrors relationships for replica."""
        LOG.debug("Cleaning up old snapmirror relationships for replica %s.",
                  replica['id'])
        src_vol_name, src_vserver, src_backend = (
            self.get_backend_info_for_share(replica))
        src_client = get_client_for_backend(src_backend,
                                            vserver_name=src_vserver)

        # replica_list may contain the replica we are trying to clean up
        destinations = (r for r in replica_list if r['id'] != replica['id'])

        for destination in destinations:
            dest_vol_name, dest_vserver, _ = (
                self.get_backend_info_for_share(destination))
            try:
                src_client.release_snapmirror_vol(
                    src_vserver, src_vol_name, dest_vserver, dest_vol_name)
            except netapp_api.NaApiError as e:
                if (e.code == netapp_api.EOBJECTNOTFOUND or
                        e.code == netapp_api.ESOURCE_IS_DIFFERENT or
                        "(entry doesn't exist)" in e.message):
                    LOG.debug(
                        'Snapmirror destination %s no longer exists for '
                        'replica %s.', destination['id'], replica['id'])
                else:
                    LOG.exception(
                        'Error releasing snapmirror destination %s for '
                        'replica %s.', destination['id'], replica['id'])
