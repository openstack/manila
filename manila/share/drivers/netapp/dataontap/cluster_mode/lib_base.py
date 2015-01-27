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
NetApp Data ONTAP cDOT storage driver library. Supports NFS & CIFS protocols.

This driver requires a Data ONTAP (Cluster-mode) storage system with
installed CIFS and/or NFS licenses.
"""

import copy
import re
import socket

from oslo_log import log
from oslo_utils import excutils
from oslo_utils import timeutils
from oslo_utils import units
import six

from manila import context
from manila import exception
from manila.i18n import _, _LE, _LI
from manila.openstack.common import loopingcall
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.protocols import cifs_cmode
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila.share.drivers.netapp import options as na_opts
from manila.share.drivers.netapp import utils as na_utils
from manila.share import utils as share_utils
from manila import utils


LOG = log.getLogger(__name__)


def ensure_vserver(f):
    def wrap(self, *args, **kwargs):
        server = kwargs.get('share_server')
        if not server:
            # For now cmode driver does not support flat networking.
            raise exception.NetAppException(_('Share server is not provided.'))
        vserver_name = server['backend_details'].get('vserver_name') if \
            server.get('backend_details') else None
        if not vserver_name:
            msg = _('Vserver name is absent in backend details. Please '
                    'check whether Vserver was created properly or not.')
            raise exception.NetAppException(msg)
        if not self._client.vserver_exists(vserver_name):
            raise exception.VserverUnavailable(vserver=vserver_name)
        return f(self, *args, **kwargs)
    return wrap


class NetAppCmodeFileStorageLibrary(object):
    """NetApp specific ONTAP Cluster mode driver.

    Supports NFS and CIFS protocols.
    Uses Data ONTAP as backend to create shares and snapshots.
    Sets up vServer for each share_network.
    Connectivity between storage and client VM is organized
    by plugging vServer's network interfaces into neutron subnet
    that VM is using.
    """

    AUTOSUPPORT_INTERVAL_SECONDS = 3600  # hourly
    SSC_UPDATE_INTERVAL_SECONDS = 3600  # hourly

    def __init__(self, db, driver_name, **kwargs):
        na_utils.validate_driver_instantiation(**kwargs)

        self.db = db
        self.driver_name = driver_name

        self._helpers = None
        self._licenses = []
        self._client = None
        self._clients = {}
        self._ssc_stats = {}
        self._last_ems = timeutils.utcnow()

        self.configuration = kwargs['configuration']
        self.configuration.append_config_values(na_opts.netapp_connection_opts)
        self.configuration.append_config_values(na_opts.netapp_basicauth_opts)
        self.configuration.append_config_values(na_opts.netapp_transport_opts)
        self.configuration.append_config_values(na_opts.netapp_support_opts)
        self.configuration.append_config_values(
            na_opts.netapp_provisioning_opts)

        self._app_version = kwargs.get('app_version', 'unknown')

        na_utils.setup_tracing(self.configuration.netapp_trace_flags)
        self._backend_name = self.configuration.safe_get(
            'share_backend_name') or driver_name

    @na_utils.trace
    def do_setup(self, context):
        self._client = self._get_api_client()
        self._setup_helpers()

    @na_utils.trace
    def check_for_setup_error(self):
        self._get_licenses()
        self._start_periodic_tasks()

    @na_utils.trace
    def _get_api_client(self, vserver=None):
        # Use cached value to prevent calls to system-get-ontapi-version.
        client = self._clients.get(vserver)

        if not client:
            client = client_cmode.NetAppCmodeClient(
                transport_type=self.configuration.netapp_transport_type,
                username=self.configuration.netapp_login,
                password=self.configuration.netapp_password,
                hostname=self.configuration.netapp_server_hostname,
                port=self.configuration.netapp_server_port,
                vserver=vserver,
                trace=na_utils.TRACE_API)
            self._clients[vserver] = client

        return client

    @na_utils.trace
    def _get_licenses(self):
        self._licenses = self._client.get_licenses()

        log_data = {
            'backend': self._backend_name,
            'licenses': ', '.join(self._licenses),
        }
        LOG.info(_LI('Available licenses on %(backend)s '
                     'are %(licenses)s.'), log_data)

        if 'nfs' not in self._licenses and 'cifs' not in self._licenses:
            msg = _LE('Neither NFS nor CIFS is licensed on %(backend)s')
            msg_args = {'backend': self._backend_name}
            LOG.error(msg % msg_args)

        return self._licenses

    def _start_periodic_tasks(self):

        # Run the task once in the current thread so prevent a race with
        # the first invocation of get_share_stats.
        self._update_ssc_info()

        ssc_periodic_task = loopingcall.FixedIntervalLoopingCall(
            self._update_ssc_info)
        ssc_periodic_task.start(interval=self.SSC_UPDATE_INTERVAL_SECONDS,
                                initial_delay=self.SSC_UPDATE_INTERVAL_SECONDS)

    @na_utils.trace
    def _get_valid_share_name(self, share_id):
        """Get share name according to share name template."""
        return self.configuration.netapp_volume_name_template % {
            'share_id': share_id.replace('-', '_')}

    @na_utils.trace
    def _get_valid_snapshot_name(self, snapshot_id):
        """Get snapshot name according to snapshot name template."""
        return 'share_snapshot_' + snapshot_id.replace('-', '_')

    @na_utils.trace
    def get_share_stats(self):
        """Retrieve stats info from Cluster Mode backend."""
        aggr_space = self._client.get_cluster_aggregate_capacities(
            self._find_matching_aggregates())

        data = {
            'share_backend_name': self._backend_name,
            'driver_name': self.driver_name,
            'vendor_name': 'NetApp',
            'driver_version': '1.0',
            'netapp_storage_family': 'ontap_cluster',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 0.0,
            'free_capacity_gb': 0.0,
        }

        pools = []
        for aggr_name in sorted(aggr_space.keys()):

            total_capacity_gb = na_utils.round_down(
                float(aggr_space[aggr_name]['total']) / units.Gi, '0.01')
            free_capacity_gb = na_utils.round_down(
                float(aggr_space[aggr_name]['available']) / units.Gi, '0.01')
            allocated_capacity_gb = na_utils.round_down(
                float(aggr_space[aggr_name]['used']) / units.Gi, '0.01')

            pool = {
                'pool_name': aggr_name,
                'total_capacity_gb': total_capacity_gb,
                'free_capacity_gb': free_capacity_gb,
                'allocated_capacity_gb': allocated_capacity_gb,
                'QoS_support': 'False',
                'reserved_percentage': 0,
            }

            # Add storage service catalog data.
            pool_ssc_stats = self._ssc_stats.get(aggr_name)
            if pool_ssc_stats:
                pool.update(pool_ssc_stats)

            pools.append(pool)

        data['pools'] = pools

        self._handle_ems_logging()

        return data

    @na_utils.trace
    def _handle_ems_logging(self):
        """Send an EMS log message if one hasn't been sent recently."""
        if timeutils.is_older_than(self._last_ems,
                                   self.AUTOSUPPORT_INTERVAL_SECONDS):
            self._last_ems = timeutils.utcnow()
            self._client.send_ems_log_message(self._build_ems_log_message())

    @na_utils.trace
    def _build_ems_log_message(self):
        """Construct EMS Autosupport log message."""

        ems_log = {
            'computer-name': socket.getfqdn() or 'Manila_node',
            'event-id': '0',
            'event-source': 'Manila driver %s' % self.driver_name,
            'app-version': self._app_version,
            'category': 'provisioning',
            'event-description': 'OpenStack Manila connected to cluster node',
            'log-level': '6',
            'auto-support': 'false',
        }

        return ems_log

    @na_utils.trace
    def _find_matching_aggregates(self):
        """Find all aggregates match pattern."""
        pattern = self.configuration.netapp_aggregate_name_search_pattern
        all_aggr_names = self._client.list_aggregates()
        matching_aggr_names = [aggr_name for aggr_name in all_aggr_names
                               if re.match(pattern, aggr_name)]
        return matching_aggr_names

    @na_utils.trace
    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {'CIFS': cifs_cmode.NetAppCmodeCIFSHelper(),
                         'NFS': nfs_cmode.NetAppCmodeNFSHelper()}

    @na_utils.trace
    def _get_helper(self, share):
        """Returns driver which implements share protocol."""
        share_protocol = share['share_proto']
        if share_protocol.lower() not in self._licenses:
            current_licenses = self._get_licenses()
            if share_protocol.lower() not in current_licenses:
                msg_args = {
                    'protocol': share_protocol,
                    'host': self.configuration.netapp_server_hostname,
                }
                msg = _('The protocol %(protocol)s is not licensed on '
                        'controller %(host)s') % msg_args
                LOG.error(msg)
                raise exception.NetAppException(msg)

        for protocol in self._helpers.keys():
            if share_protocol.upper().startswith(protocol):
                return self._helpers[protocol]

        err_msg = _("Invalid NAS protocol supplied: %s. ") % share_protocol
        raise exception.NetAppException(err_msg)

    @na_utils.trace
    def setup_server(self, network_info, metadata=None):
        """Creates and configures new Vserver."""
        LOG.debug('Creating server %s', network_info['server_id'])
        vserver_name = self._create_vserver_if_nonexistent(network_info)
        return {'vserver_name': vserver_name}

    @na_utils.trace
    def _create_vserver_if_nonexistent(self, network_info):
        """Creates Vserver with given parameters if it doesn't exist."""
        vserver_name = (self.configuration.netapp_vserver_name_template %
                        network_info['server_id'])
        context_adm = context.get_admin_context()
        self.db.share_server_backend_details_set(
            context_adm,
            network_info['server_id'],
            {'vserver_name': vserver_name},
        )

        if self._client.vserver_exists(vserver_name):
            msg = _('Vserver %s already exists.')
            raise exception.NetAppException(msg % vserver_name)

        LOG.debug('Vserver %s does not exist, creating.', vserver_name)
        self._client.create_vserver(
            vserver_name,
            self.configuration.netapp_root_volume_aggregate,
            self.configuration.netapp_root_volume,
            self._find_matching_aggregates())

        vserver_client = self._get_api_client(vserver=vserver_name)
        try:
            self._create_vserver_lifs(vserver_name,
                                      vserver_client,
                                      network_info)
        except netapp_api.NaApiError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to create network interface(s)."))
                self._client.delete_vserver(vserver_name, vserver_client)

        vserver_client.enable_nfs()

        security_services = network_info.get('security_services')
        if security_services:
            self._client.setup_security_services(security_services,
                                                 vserver_client,
                                                 vserver_name)
        return vserver_name

    @na_utils.trace
    def _create_vserver_lifs(self, vserver_name, vserver_client,
                             network_info):

        nodes = self._client.list_cluster_nodes()
        node_network_info = zip(nodes, network_info['network_allocations'])
        netmask = utils.cidr_to_netmask(network_info['cidr'])

        for node, net_info in node_network_info:
            net_id = net_info['id']
            port = self._client.get_node_data_port(node)
            ip = net_info['ip_address']
            self._create_lif_if_nonexistent(vserver_name,
                                            net_id,
                                            network_info['segmentation_id'],
                                            node,
                                            port,
                                            ip,
                                            netmask,
                                            vserver_client)

    @na_utils.trace
    def _create_lif_if_nonexistent(self, vserver_name, allocation_id, vlan,
                                   node, port, ip, netmask, vserver_client):
        """Creates LIF for Vserver."""
        if not vserver_client.network_interface_exists(vserver_name, node,
                                                       port, ip, netmask,
                                                       vlan):
            self._client.create_network_interface(
                ip, netmask, vlan, node, port, vserver_name, allocation_id,
                self.configuration.netapp_lif_name_template)

    @na_utils.trace
    def get_pool(self, share):
        pool = share_utils.extract_host(share['host'], level='pool')
        if pool:
            return pool

        volume_name = self._get_valid_share_name(share['id'])
        return self._client.get_aggregate_for_volume(volume_name)

    @ensure_vserver
    @na_utils.trace
    def create_share(self, context, share, share_server):
        """Creates new share."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = self._get_api_client(vserver=vserver)
        self._allocate_container(share, vserver, vserver_client)
        return self._create_export(share, vserver, vserver_client)

    @ensure_vserver
    @na_utils.trace
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Creates new share from snapshot."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = self._get_api_client(vserver=vserver)
        self._allocate_container_from_snapshot(share, snapshot, vserver_client)
        return self._create_export(share, vserver, vserver_client)

    @na_utils.trace
    def _allocate_container(self, share, vserver, vserver_client):
        """Create new share on aggregate."""
        share_name = self._get_valid_share_name(share['id'])

        # Get Data ONTAP aggregate name as pool name.
        aggregate_name = share_utils.extract_host(share['host'], level='pool')

        if aggregate_name is None:
            msg = _("Pool is not available in the share host field.")
            raise exception.InvalidHost(reason=msg)

        LOG.debug('Creating volume %(share_name)s on aggregate %(aggregate)s',
                  {'share_name': share_name, 'aggregate': aggregate_name})
        vserver_client.create_volume(aggregate_name, share_name, share['size'])

    @na_utils.trace
    def _allocate_container_from_snapshot(self, share, snapshot,
                                          vserver_client):
        """Clones existing share."""
        share_name = self._get_valid_share_name(share['id'])
        parent_share_name = self._get_valid_share_name(snapshot['share_id'])
        parent_snapshot_name = self._get_valid_snapshot_name(snapshot['id'])

        LOG.debug('Creating volume from snapshot %s', snapshot['id'])
        vserver_client.create_volume_clone(share_name, parent_share_name,
                                           parent_snapshot_name)

    def _share_exists(self, share_name, vserver_client):
        return vserver_client.volume_exists(share_name)

    @ensure_vserver
    @na_utils.trace
    def delete_share(self, context, share, share_server=None):
        """Deletes share."""
        share_name = self._get_valid_share_name(share['id'])
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = self._get_api_client(vserver=vserver)
        if self._share_exists(share_name, vserver_client):
            self._remove_export(share, vserver_client)
            self._deallocate_container(share_name, vserver_client)
        else:
            LOG.info(_LI("Share %s does not exist."), share['id'])

    @na_utils.trace
    def _deallocate_container(self, share_name, vserver_client):
        """Free share space."""
        vserver_client.unmount_volume(share_name, force=True)
        vserver_client.offline_volume(share_name)
        vserver_client.delete_volume(share_name)

    @na_utils.trace
    def _create_export(self, share, vserver, vserver_client):
        """Creates NAS storage."""
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        share_name = self._get_valid_share_name(share['id'])

        interfaces = vserver_client.get_network_interfaces()
        if not interfaces:
            msg = _("Cannot find network interfaces for Vserver %s.")
            raise exception.NetAppException(msg % vserver)

        ip_address = interfaces[0]['address']
        export_location = helper.create_share(share_name, ip_address)
        return export_location

    @na_utils.trace
    def _remove_export(self, share, vserver_client):
        """Deletes NAS storage."""
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        target = helper.get_target(share)
        # Share may be in error state, so there's no share and target.
        if target:
            helper.delete_share(share)

    @ensure_vserver
    @na_utils.trace
    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of a share."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = self._get_api_client(vserver=vserver)
        share_name = self._get_valid_share_name(snapshot['share_id'])
        snapshot_name = self._get_valid_snapshot_name(snapshot['id'])
        LOG.debug('Creating snapshot %s', snapshot_name)
        vserver_client.create_snapshot(share_name, snapshot_name)

    @ensure_vserver
    @na_utils.trace
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot of a share."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = self._get_api_client(vserver=vserver)
        share_name = self._get_valid_share_name(snapshot['share_id'])
        snapshot_name = self._get_valid_snapshot_name(snapshot['id'])

        if vserver_client.is_snapshot_busy(share_name, snapshot_name):
            raise exception.ShareSnapshotIsBusy(snapshot_name=snapshot_name)

        LOG.debug('Deleting snapshot %(snap)s for share %(share)s.',
                  {'snap': snapshot_name, 'share': share_name})
        vserver_client.delete_snapshot(share_name, snapshot_name)

    @ensure_vserver
    @na_utils.trace
    def allow_access(self, context, share, access, share_server=None):
        """Allows access to a given NAS storage."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = self._get_api_client(vserver=vserver)
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        helper.allow_access(context, share, access)

    @ensure_vserver
    @na_utils.trace
    def deny_access(self, context, share, access, share_server=None):
        """Denies access to a given NAS storage."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = self._get_api_client(vserver=vserver)
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        helper.deny_access(context, share, access)

    @na_utils.trace
    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        return len(self._client.list_cluster_nodes())

    @na_utils.trace
    def teardown_server(self, server_details, security_services=None):
        """Teardown share network."""
        vserver = server_details['vserver_name']
        vserver_client = self._get_api_client(vserver=vserver)
        self._client.delete_vserver(vserver, vserver_client,
                                    security_services=security_services)

    def _update_ssc_info(self):
        """Periodically runs to update Storage Service Catalog data.

        The self._ssc_stats attribute is updated with the following format.
        {<aggregate_name> : {<ssc_key>: <ssc_value>}}
        """
        LOG.info(_LI("Updating storage service catalog information for "
                     "backend '%s'"), self._backend_name)

        # Work on a copy and update the ssc data atomically before returning.
        ssc_stats = copy.deepcopy(self._ssc_stats)

        aggregate_names = self._find_matching_aggregates()

        # Initialize entries for each aggregate.
        for aggregate_name in aggregate_names:
            if aggregate_name not in ssc_stats:
                ssc_stats[aggregate_name] = {}

        if aggregate_names:
            self._update_ssc_aggr_info(aggregate_names, ssc_stats)

        self._ssc_stats = ssc_stats

    def _update_ssc_aggr_info(self, aggregate_names, ssc_stats):
        """Updates the given SSC dictionary with new disk type information.

        :param volume_groups: The volume groups this driver cares about
        :param ssc_stats: The dictionary to update
        """

        raid_types = self._client.get_aggregate_raid_types(aggregate_names)
        for aggregate_name, raid_type in six.iteritems(raid_types):
            ssc_stats[aggregate_name]['netapp_raid_type'] = raid_type

        disk_types = self._client.get_aggregate_disk_types(aggregate_names)
        for aggregate_name, disk_type in six.iteritems(disk_types):
            ssc_stats[aggregate_name]['netapp_disk_type'] = disk_type
