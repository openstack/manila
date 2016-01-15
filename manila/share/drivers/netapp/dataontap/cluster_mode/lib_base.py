# Copyright (c) 2015 Clinton Knight.  All rights reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
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
NetApp Data ONTAP cDOT base storage driver library.

This library is the abstract base for subclasses that complete the
single-SVM or multi-SVM functionality needed by the cDOT Manila drivers.
"""

import copy
import math
import socket
import time

from oslo_log import log
from oslo_service import loopingcall
from oslo_utils import units
import six

from manila import exception
from manila.i18n import _, _LE, _LI, _LW
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.protocols import cifs_cmode
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila.share.drivers.netapp import options as na_opts
from manila.share.drivers.netapp import utils as na_utils
from manila.share import share_types
from manila.share import utils as share_utils

LOG = log.getLogger(__name__)


class NetAppCmodeFileStorageLibrary(object):

    AUTOSUPPORT_INTERVAL_SECONDS = 3600  # hourly
    SSC_UPDATE_INTERVAL_SECONDS = 3600  # hourly
    HOUSEKEEPING_INTERVAL_SECONDS = 600  # ten minutes

    SUPPORTED_PROTOCOLS = ('nfs', 'cifs')

    # Maps NetApp qualified extra specs keys to corresponding backend API
    # client library argument keywords.  When we expose more backend
    # capabilities here, we will add them to this map.
    BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP = {
        'netapp:thin_provisioned': 'thin_provisioned',
        'netapp:dedup': 'dedup_enabled',
        'netapp:compression': 'compression_enabled',
    }
    STRING_QUALIFIED_EXTRA_SPECS_MAP = {
        'netapp:snapshot_policy': 'snapshot_policy',
        'netapp:language': 'language',
        'netapp:max_files': 'max_files',
    }
    # Maps standard extra spec keys to legacy NetApp keys
    STANDARD_BOOLEAN_EXTRA_SPECS_MAP = {
        'thin_provisioning': 'netapp:thin_provisioned',
        'dedupe': 'netapp:dedup',
        'compression': 'netapp:compression',
    }

    def __init__(self, driver_name, **kwargs):
        na_utils.validate_driver_instantiation(**kwargs)

        self.driver_name = driver_name

        self.private_storage = kwargs['private_storage']
        self.configuration = kwargs['configuration']
        self.configuration.append_config_values(na_opts.netapp_connection_opts)
        self.configuration.append_config_values(na_opts.netapp_basicauth_opts)
        self.configuration.append_config_values(na_opts.netapp_transport_opts)
        self.configuration.append_config_values(na_opts.netapp_support_opts)
        self.configuration.append_config_values(na_opts.netapp_cluster_opts)
        self.configuration.append_config_values(
            na_opts.netapp_provisioning_opts)

        self._licenses = []
        self._client = None
        self._clients = {}
        self._ssc_stats = {}
        self._have_cluster_creds = None

        self._app_version = kwargs.get('app_version', 'unknown')

        na_utils.setup_tracing(self.configuration.netapp_trace_flags)
        self._backend_name = self.configuration.safe_get(
            'share_backend_name') or driver_name

    @na_utils.trace
    def do_setup(self, context):
        self._client = self._get_api_client()
        self._have_cluster_creds = self._client.check_for_cluster_credentials()

    @na_utils.trace
    def check_for_setup_error(self):
        self._licenses = self._get_licenses()
        self._start_periodic_tasks()

    def _get_vserver(self, share_server=None):
        raise NotImplementedError()

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

        if not self._have_cluster_creds:
            LOG.debug('License info not available without cluster credentials')
            return []

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

    @na_utils.trace
    def _start_periodic_tasks(self):

        # Run the task once in the current thread so prevent a race with
        # the first invocation of get_share_stats.
        self._update_ssc_info()

        # Start the task that updates the slow-changing storage service catalog
        ssc_periodic_task = loopingcall.FixedIntervalLoopingCall(
            self._update_ssc_info)
        ssc_periodic_task.start(interval=self.SSC_UPDATE_INTERVAL_SECONDS,
                                initial_delay=self.SSC_UPDATE_INTERVAL_SECONDS)

        # Start the task that logs autosupport (EMS) data to the controller
        ems_periodic_task = loopingcall.FixedIntervalLoopingCall(
            self._handle_ems_logging)
        ems_periodic_task.start(interval=self.AUTOSUPPORT_INTERVAL_SECONDS,
                                initial_delay=0)

        # Start the task that runs other housekeeping tasks, such as deletion
        # of previously soft-deleted storage artifacts.
        housekeeping_periodic_task = loopingcall.FixedIntervalLoopingCall(
            self._handle_housekeeping_tasks)
        housekeeping_periodic_task.start(
            interval=self.HOUSEKEEPING_INTERVAL_SECONDS, initial_delay=0)

    def _get_valid_share_name(self, share_id):
        """Get share name according to share name template."""
        return self.configuration.netapp_volume_name_template % {
            'share_id': share_id.replace('-', '_')}

    def _get_valid_snapshot_name(self, snapshot_id):
        """Get snapshot name according to snapshot name template."""
        return 'share_snapshot_' + snapshot_id.replace('-', '_')

    def _get_valid_cg_snapshot_name(self, snapshot_id):
        """Get snapshot name according to snapshot name template."""
        return 'share_cg_snapshot_' + snapshot_id.replace('-', '_')

    @na_utils.trace
    def _get_aggregate_space(self):
        aggregates = self._find_matching_aggregates()
        if self._have_cluster_creds:
            return self._client.get_cluster_aggregate_capacities(aggregates)
        else:
            return self._client.get_vserver_aggregate_capacities(aggregates)

    @na_utils.trace
    def _get_aggregate_node(self, aggregate_name):
        """Get home node for the specified aggregate, or None."""
        if self._have_cluster_creds:
            return self._client.get_node_for_aggregate(aggregate_name)
        else:
            return None

    @na_utils.trace
    def get_share_stats(self):
        """Retrieve stats info from Data ONTAP backend."""

        data = {
            'share_backend_name': self._backend_name,
            'driver_name': self.driver_name,
            'vendor_name': 'NetApp',
            'driver_version': '1.0',
            'netapp_storage_family': 'ontap_cluster',
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 0.0,
            'free_capacity_gb': 0.0,
            'consistency_group_support': 'host',
            'pools': self._get_pools(),
        }
        return data

    @na_utils.trace
    def get_share_server_pools(self, share_server):
        """Return list of pools related to a particular share server.

        Note that the multi-SVM cDOT driver assigns all available pools to
        each Vserver, so there is no need to filter the pools any further
        by share_server.

        :param share_server: ShareServer class instance.
        """
        return self._get_pools()

    @na_utils.trace
    def _get_pools(self):
        """Retrieve list of pools available to this backend."""

        pools = []
        aggr_space = self._get_aggregate_space()

        for aggr_name in sorted(aggr_space.keys()):

            total_capacity_gb = na_utils.round_down(float(
                aggr_space[aggr_name].get('total', 0)) / units.Gi, '0.01')
            free_capacity_gb = na_utils.round_down(float(
                aggr_space[aggr_name].get('available', 0)) / units.Gi, '0.01')
            allocated_capacity_gb = na_utils.round_down(float(
                aggr_space[aggr_name].get('used', 0)) / units.Gi, '0.01')

            if total_capacity_gb == 0.0:
                total_capacity_gb = 'unknown'

            pool = {
                'pool_name': aggr_name,
                'total_capacity_gb': total_capacity_gb,
                'free_capacity_gb': free_capacity_gb,
                'allocated_capacity_gb': allocated_capacity_gb,
                'qos': 'False',
                'reserved_percentage': 0,
                'dedupe': [True, False],
                'compression': [True, False],
                'thin_provisioning': [True, False],
            }

            # Add storage service catalog data.
            pool_ssc_stats = self._ssc_stats.get(aggr_name)
            if pool_ssc_stats:
                pool.update(pool_ssc_stats)

            pools.append(pool)

        return pools

    @na_utils.trace
    def _handle_ems_logging(self):
        """Build and send an EMS log message."""
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
    def _handle_housekeeping_tasks(self):
        """Handle various cleanup activities."""

    def _find_matching_aggregates(self):
        """Find all aggregates match pattern."""
        raise NotImplementedError()

    @na_utils.trace
    def _get_helper(self, share):
        """Returns driver which implements share protocol."""
        share_protocol = share['share_proto'].lower()

        if share_protocol not in self.SUPPORTED_PROTOCOLS:
            err_msg = _("Invalid NAS protocol supplied: %s.") % share_protocol
            raise exception.NetAppException(err_msg)

        self._check_license_for_protocol(share_protocol)

        if share_protocol == 'nfs':
            return nfs_cmode.NetAppCmodeNFSHelper()
        elif share_protocol == 'cifs':
            return cifs_cmode.NetAppCmodeCIFSHelper()

    @na_utils.trace
    def _check_license_for_protocol(self, share_protocol):
        """Validates protocol license if cluster APIs are accessible."""
        if not self._have_cluster_creds:
            return

        if share_protocol.lower() not in self._licenses:
            current_licenses = self._get_licenses()
            if share_protocol.lower() not in current_licenses:
                msg_args = {
                    'protocol': share_protocol,
                    'host': self.configuration.netapp_server_hostname
                }
                msg = _('The protocol %(protocol)s is not licensed on '
                        'controller %(host)s') % msg_args
                LOG.error(msg)
                raise exception.NetAppException(msg)

    @na_utils.trace
    def get_pool(self, share):
        pool = share_utils.extract_host(share['host'], level='pool')
        if pool:
            return pool

        share_name = self._get_valid_share_name(share['id'])
        return self._client.get_aggregate_for_volume(share_name)

    @na_utils.trace
    def create_share(self, context, share, share_server):
        """Creates new share."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        self._allocate_container(share, vserver_client)
        return self._create_export(share, vserver, vserver_client)

    @na_utils.trace
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Creates new share from snapshot."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        self._allocate_container_from_snapshot(share, snapshot, vserver_client)
        return self._create_export(share, vserver, vserver_client)

    @na_utils.trace
    def _allocate_container(self, share, vserver_client):
        """Create new share on aggregate."""
        share_name = self._get_valid_share_name(share['id'])

        # Get Data ONTAP aggregate name as pool name.
        pool_name = share_utils.extract_host(share['host'], level='pool')
        if pool_name is None:
            msg = _("Pool is not available in the share host field.")
            raise exception.InvalidHost(reason=msg)

        extra_specs = share_types.get_extra_specs_from_share(share)
        extra_specs = self._remap_standard_boolean_extra_specs(extra_specs)
        self._check_extra_specs_validity(share, extra_specs)
        provisioning_options = self._get_provisioning_options(extra_specs)

        LOG.debug('Creating share %(share)s on pool %(pool)s with '
                  'provisioning options %(options)s',
                  {'share': share_name, 'pool': pool_name,
                   'options': provisioning_options})
        vserver_client.create_volume(
            pool_name, share_name, share['size'],
            snapshot_reserve=self.configuration.
            netapp_volume_snapshot_reserve_percent, **provisioning_options)

    @na_utils.trace
    def _remap_standard_boolean_extra_specs(self, extra_specs):
        """Replace standard boolean extra specs with NetApp-specific ones."""
        specs = copy.deepcopy(extra_specs)
        for (key, netapp_key) in self.STANDARD_BOOLEAN_EXTRA_SPECS_MAP.items():
            if key in specs:
                bool_value = share_types.parse_boolean_extra_spec(key,
                                                                  specs[key])
                specs[netapp_key] = 'true' if bool_value else 'false'
                del specs[key]
        return specs

    @na_utils.trace
    def _check_extra_specs_validity(self, share, extra_specs):
        """Check if the extra_specs have valid values."""
        self._check_boolean_extra_specs_validity(
            share, extra_specs, list(self.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP))
        self._check_string_extra_specs_validity(share, extra_specs)

    @na_utils.trace
    def _check_string_extra_specs_validity(self, share, extra_specs):
        """Check if the string_extra_specs have valid values."""
        if 'netapp:max_files' in extra_specs:
            self._check_if_max_files_is_valid(share,
                                              extra_specs['netapp:max_files'])

    @na_utils.trace
    def _check_if_max_files_is_valid(self, share, value):
        """Check if max_files has a valid value."""
        if int(value) < 0:
            args = {'value': value, 'key': 'netapp:max_files',
                    'type_id': share['share_type_id'], 'share_id': share['id']}
            msg = _('Invalid value "%(value)s" for extra_spec "%(key)s" '
                    'in share_type %(type_id)s for share %(share_id)s.')
            raise exception.NetAppException(msg % args)

    @na_utils.trace
    def _check_boolean_extra_specs_validity(self, share, specs,
                                            keys_of_interest):
        # cDOT compression requires deduplication.
        dedup = specs.get('netapp:dedup', None)
        compression = specs.get('netapp:compression', None)
        if dedup is not None and compression is not None:
            if dedup.lower() == 'false' and compression.lower() == 'true':
                spec = {'netapp:dedup': dedup,
                        'netapp:compression': compression}
                type_id = share['share_type_id']
                share_id = share['id']
                args = {'type_id': type_id, 'share_id': share_id, 'spec': spec}
                msg = _('Invalid combination of extra_specs in share_type '
                        '%(type_id)s for share %(share_id)s: %(spec)s: '
                        'deduplication must be enabled in order for '
                        'compression to be enabled.')
                raise exception.Invalid(msg % args)
        """Check if the boolean_extra_specs have valid values."""
        # Extra spec values must be (ignoring case) 'true' or 'false'.
        for key in keys_of_interest:
            value = specs.get(key)
            if value is not None and value.lower() not in ['true', 'false']:
                type_id = share['share_type_id']
                share_id = share['id']
                arg_map = {'value': value, 'key': key, 'type_id': type_id,
                           'share_id': share_id}
                msg = _('Invalid value "%(value)s" for extra_spec "%(key)s" '
                        'in share_type %(type_id)s for share %(share_id)s.')
                raise exception.Invalid(msg % arg_map)

    @na_utils.trace
    def _get_boolean_provisioning_options(self, specs, boolean_specs_map):
        """Given extra specs, return corresponding client library kwargs.

        Build a full set of client library provisioning kwargs, filling in a
        default value if an explicit value has not been supplied via a
        corresponding extra spec.  Boolean extra spec values are "true" or
        "false", with missing specs treated as "false".  Provisioning kwarg
        values are True or False.
        """
        # Extract the extra spec keys of concern and their corresponding
        # kwarg keys as lists.
        keys_of_interest = list(boolean_specs_map)
        provisioning_args = [boolean_specs_map[key]
                             for key in keys_of_interest]
        # Set missing spec values to 'false'
        for key in keys_of_interest:
            if key not in specs:
                specs[key] = 'false'
        # Build a list of Boolean provisioning arguments from the string
        # equivalents in the spec values.
        provisioning_values = [specs[key].lower() == 'true' for key in
                               keys_of_interest]
        # Combine the list of provisioning args and the list of provisioning
        # values into a dictionary suitable for use as kwargs when invoking
        # provisioning methods from the client API library.
        return dict(zip(provisioning_args, provisioning_values))

    @na_utils.trace
    def _get_string_provisioning_options(self, specs, string_specs_map):
        """Given extra specs, return corresponding client library kwargs.

        Build a full set of client library provisioning kwargs, filling in a
        default value if an explicit value has not been supplied via a
        corresponding extra spec.
        """
        # Extract the extra spec keys of concern and their corresponding
        # kwarg keys as lists.
        keys_of_interest = list(string_specs_map)
        provisioning_args = [string_specs_map[key]
                             for key in keys_of_interest]
        # Set missing spec values to 'false'
        for key in keys_of_interest:
            if key not in specs:
                specs[key] = None
        provisioning_values = [specs[key] for key in keys_of_interest]

        # Combine the list of provisioning args and the list of provisioning
        # values into a dictionary suitable for use as kwargs when invoking
        # provisioning methods from the client API library.
        return dict(zip(provisioning_args, provisioning_values))

    @na_utils.trace
    def _get_provisioning_options(self, specs):
        """Return a merged result of string and binary provisioning options."""
        boolean_args = self._get_boolean_provisioning_options(
            specs, self.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)

        string_args = self._get_string_provisioning_options(
            specs, self.STRING_QUALIFIED_EXTRA_SPECS_MAP)
        result = boolean_args.copy()
        result.update(string_args)
        return result

    @na_utils.trace
    def _check_aggregate_extra_specs_validity(self, aggregate_name, specs):

        for specs_key in ('netapp_disk_type', 'netapp_raid_type'):
            aggr_value = self._ssc_stats.get(aggregate_name, {}).get(specs_key)
            specs_value = specs.get(specs_key)

            if aggr_value and specs_value and aggr_value != specs_value:
                msg = _('Invalid value "%(value)s" for extra_spec "%(key)s" '
                        'in aggregate %(aggr)s.')
                msg_args = {
                    'value': specs_value,
                    'key': specs_key,
                    'aggr': aggregate_name
                }
                raise exception.NetAppException(msg % msg_args)

    @na_utils.trace
    def _allocate_container_from_snapshot(
            self, share, snapshot, vserver_client,
            snapshot_name_func=_get_valid_snapshot_name):
        """Clones existing share."""
        share_name = self._get_valid_share_name(share['id'])
        parent_share_name = self._get_valid_share_name(snapshot['share_id'])
        parent_snapshot_name = snapshot_name_func(self, snapshot['id'])

        LOG.debug('Creating share from snapshot %s', snapshot['id'])
        vserver_client.create_volume_clone(share_name, parent_share_name,
                                           parent_snapshot_name)
        vserver_client.split_volume_clone(share_name)

    @na_utils.trace
    def _share_exists(self, share_name, vserver_client):
        return vserver_client.volume_exists(share_name)

    @na_utils.trace
    def delete_share(self, context, share, share_server=None):
        """Deletes share."""
        try:
            vserver, vserver_client = self._get_vserver(
                share_server=share_server)
        except (exception.InvalidInput,
                exception.VserverNotSpecified,
                exception.VserverNotFound) as error:
            LOG.warning(_LW("Could not determine share server for share being "
                            "deleted: %(share)s. Deletion of share record "
                            "will proceed anyway. Error: %(error)s"),
                        {'share': share['id'], 'error': error})
            return

        share_name = self._get_valid_share_name(share['id'])
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

        interfaces = vserver_client.get_network_interfaces(
            protocols=[share['share_proto']])

        if not interfaces:
            msg = _('Cannot find network interfaces for Vserver %(vserver)s '
                    'and protocol %(proto)s.')
            msg_args = {'vserver': vserver, 'proto': share['share_proto']}
            raise exception.NetAppException(msg % msg_args)

        interfaces = self._sort_lifs_by_aggregate_locality(share, interfaces)

        export_addresses = [interface['address'] for interface in interfaces]
        export_locations = helper.create_share(
            share, share_name, export_addresses)
        return export_locations

    @na_utils.trace
    def _sort_lifs_by_aggregate_locality(self, share, interfaces):
        """Sort LIFs by placing aggregate-local LIFs first."""
        aggregate_name = share_utils.extract_host(share['host'], level='pool')
        home_node = self._get_aggregate_node(aggregate_name)
        if not home_node:
            return interfaces

        return sorted(interfaces,
                      key=lambda intf: intf.get('home-node') != home_node)

    @na_utils.trace
    def _remove_export(self, share, vserver_client):
        """Deletes NAS storage."""
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        share_name = self._get_valid_share_name(share['id'])
        target = helper.get_target(share)
        # Share may be in error state, so there's no share and target.
        if target:
            helper.delete_share(share, share_name)

    @na_utils.trace
    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of a share."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_valid_share_name(snapshot['share_id'])
        snapshot_name = self._get_valid_snapshot_name(snapshot['id'])
        LOG.debug('Creating snapshot %s', snapshot_name)
        vserver_client.create_snapshot(share_name, snapshot_name)

    @na_utils.trace
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot of a share."""
        try:
            vserver, vserver_client = self._get_vserver(
                share_server=share_server)
        except (exception.InvalidInput,
                exception.VserverNotSpecified,
                exception.VserverNotFound) as error:
            LOG.warning(_LW("Could not determine share server for snapshot "
                            "being deleted: %(snap)s. Deletion of snapshot "
                            "record will proceed anyway. Error: %(error)s"),
                        {'snap': snapshot['id'], 'error': error})
            return

        share_name = self._get_valid_share_name(snapshot['share_id'])
        snapshot_name = self._get_valid_snapshot_name(snapshot['id'])

        try:
            self._handle_busy_snapshot(vserver_client, share_name,
                                       snapshot_name)
        except exception.SnapshotNotFound:
            LOG.info(_LI("Snapshot %s does not exist."), snapshot_name)
            return

        LOG.debug('Deleting snapshot %(snap)s for share %(share)s.',
                  {'snap': snapshot_name, 'share': share_name})
        vserver_client.delete_snapshot(share_name, snapshot_name)

    @na_utils.trace
    def _handle_busy_snapshot(self, vserver_client, share_name, snapshot_name,
                              wait_seconds=60):
        """Checks for and handles a busy snapshot.

        If a snapshot is not busy, take no action.  If a snapshot is busy for
        reasons other than a clone dependency, raise immediately.  Otherwise,
        since we always start a clone split operation after cloning a share,
        wait up to a minute for a clone dependency to clear before giving up.
        """
        snapshot = vserver_client.get_snapshot(share_name, snapshot_name)
        if not snapshot['busy']:
            return

        # Fail fast if snapshot is not busy due to a clone dependency
        if snapshot['owners'] != {'volume clone'}:
            raise exception.ShareSnapshotIsBusy(snapshot_name=snapshot_name)

        # Wait for clone dependency to clear.
        retry_interval = 3  # seconds
        for retry in range(int(wait_seconds / retry_interval)):
            LOG.debug('Snapshot %(snap)s for share %(share)s is busy, waiting '
                      'for volume clone dependency to clear.',
                      {'snap': snapshot_name, 'share': share_name})

            time.sleep(retry_interval)
            snapshot = vserver_client.get_snapshot(share_name, snapshot_name)
            if not snapshot['busy']:
                return

        raise exception.ShareSnapshotIsBusy(snapshot_name=snapshot_name)

    @na_utils.trace
    def manage_existing(self, share, driver_options):
        vserver, vserver_client = self._get_vserver(share_server=None)
        share_size = self._manage_container(share, vserver_client)
        export_locations = self._create_export(share, vserver, vserver_client)
        return {'size': share_size, 'export_locations': export_locations}

    @na_utils.trace
    def unmanage(self, share):
        pass

    @na_utils.trace
    def _manage_container(self, share, vserver_client):
        """Bring existing volume under management as a share."""

        protocol_helper = self._get_helper(share)
        protocol_helper.set_client(vserver_client)

        volume_name = protocol_helper.get_share_name_for_share(share)
        if not volume_name:
            msg = _('Volume could not be determined from export location '
                    '%(export)s.')
            msg_args = {'export': share['export_location']}
            raise exception.ManageInvalidShare(reason=msg % msg_args)

        share_name = self._get_valid_share_name(share['id'])
        aggregate_name = share_utils.extract_host(share['host'], level='pool')

        # Get existing volume info
        volume = vserver_client.get_volume_to_manage(aggregate_name,
                                                     volume_name)
        if not volume:
            msg = _('Volume %(volume)s not found on aggregate %(aggr)s.')
            msg_args = {'volume': volume_name, 'aggr': aggregate_name}
            raise exception.ManageInvalidShare(reason=msg % msg_args)

        # Ensure volume is manageable
        self._validate_volume_for_manage(volume, vserver_client)

        # Validate extra specs
        extra_specs = share_types.get_extra_specs_from_share(share)
        try:
            self._check_extra_specs_validity(share, extra_specs)
            self._check_aggregate_extra_specs_validity(aggregate_name,
                                                       extra_specs)
        except exception.ManilaException as ex:
            raise exception.ManageExistingShareTypeMismatch(
                reason=six.text_type(ex))
        provisioning_options = self._get_provisioning_options(extra_specs)

        debug_args = {
            'share': share_name,
            'aggr': aggregate_name,
            'options': provisioning_options
        }
        LOG.debug('Managing share %(share)s on aggregate %(aggr)s with '
                  'provisioning options %(options)s', debug_args)

        # Rename & remount volume on new path
        vserver_client.unmount_volume(volume_name)
        vserver_client.set_volume_name(volume_name, share_name)
        vserver_client.mount_volume(share_name)

        # Modify volume to match extra specs
        vserver_client.manage_volume(aggregate_name, share_name,
                                     **provisioning_options)

        # Save original volume info to private storage
        original_data = {
            'original_name': volume['name'],
            'original_junction_path': volume['junction-path']
        }
        self.private_storage.update(share['id'], original_data)

        # When calculating the size, round up to the next GB.
        return int(math.ceil(float(volume['size']) / units.Gi))

    @na_utils.trace
    def _validate_volume_for_manage(self, volume, vserver_client):
        """Ensure volume is a candidate for becoming a share."""

        # Check volume info, extra specs validity
        if volume['type'] != 'rw' or volume['style'] != 'flex':
            msg = _('Volume %(volume)s must be a read-write flexible volume.')
            msg_args = {'volume': volume['name']}
            raise exception.ManageInvalidShare(reason=msg % msg_args)

        if vserver_client.volume_has_luns(volume['name']):
            msg = _('Volume %(volume)s must not contain LUNs.')
            msg_args = {'volume': volume['name']}
            raise exception.ManageInvalidShare(reason=msg % msg_args)

        if vserver_client.volume_has_junctioned_volumes(volume['name']):
            msg = _('Volume %(volume)s must not have junctioned volumes.')
            msg_args = {'volume': volume['name']}
            raise exception.ManageInvalidShare(reason=msg % msg_args)

    @na_utils.trace
    def create_consistency_group(self, context, cg_dict, share_server=None):
        """Creates a consistency group.

        cDOT has no persistent CG object, so apart from validating the
        share_server info is passed correctly, this method has nothing to do.
        """
        vserver, vserver_client = self._get_vserver(share_server=share_server)

    @na_utils.trace
    def create_consistency_group_from_cgsnapshot(
            self, context, cg_dict, cgsnapshot_dict, share_server=None):
        """Creates a consistency group from an existing CG snapshot."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)

        # Ensure there is something to do
        if not cgsnapshot_dict['cgsnapshot_members']:
            return None, None

        clone_list = self._collate_cg_snapshot_info(cg_dict, cgsnapshot_dict)
        share_update_list = []

        LOG.debug('Creating consistency group from CG snapshot %s.',
                  cgsnapshot_dict['id'])

        for clone in clone_list:

            self._allocate_container_from_snapshot(
                clone['share'], clone['snapshot'], vserver_client,
                NetAppCmodeFileStorageLibrary._get_valid_cg_snapshot_name)

            export_locations = self._create_export(clone['share'],
                                                   vserver,
                                                   vserver_client)
            share_update_list.append({
                'id': clone['share']['id'],
                'export_locations': export_locations,
            })

        return None, share_update_list

    def _collate_cg_snapshot_info(self, cg_dict, cgsnapshot_dict):
        """Collate the data for a clone of a CG snapshot.

        Given two data structures, a CG snapshot (cgsnapshot_dict) and a new
        CG to be cloned from the snapshot (cg_dict), match up both structures
        into a list of dicts (share & snapshot) suitable for use by existing
        driver methods that clone individual share snapshots.
        """

        clone_list = list()

        for share in cg_dict['shares']:

            clone_info = {'share': share}

            for cgsnapshot_member in cgsnapshot_dict['cgsnapshot_members']:
                if (share['source_cgsnapshot_member_id'] ==
                        cgsnapshot_member['id']):
                    clone_info['snapshot'] = {
                        'share_id': cgsnapshot_member['share_id'],
                        'id': cgsnapshot_member['cgsnapshot_id']
                    }
                    break

            else:
                msg = _("Invalid data supplied for creating consistency group "
                        "from CG snapshot %s.") % cgsnapshot_dict['id']
                raise exception.InvalidConsistencyGroup(reason=msg)

            clone_list.append(clone_info)

        return clone_list

    @na_utils.trace
    def delete_consistency_group(self, context, cg_dict, share_server=None):
        """Deletes a consistency group.

        cDOT has no persistent CG object, so apart from validating the
        share_server info is passed correctly, this method has nothing to do.
        """
        try:
            vserver, vserver_client = self._get_vserver(
                share_server=share_server)
        except (exception.InvalidInput,
                exception.VserverNotSpecified,
                exception.VserverNotFound) as error:
            LOG.warning(_LW("Could not determine share server for consistency "
                            "group being deleted: %(cg)s. Deletion of CG "
                            "record will proceed anyway. Error: %(error)s"),
                        {'cg': cg_dict['id'], 'error': error})

    @na_utils.trace
    def create_cgsnapshot(self, context, snap_dict, share_server=None):
        """Creates a consistency group snapshot."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)

        share_names = [self._get_valid_share_name(member['share_id'])
                       for member in snap_dict.get('cgsnapshot_members', [])]
        snapshot_name = self._get_valid_cg_snapshot_name(snap_dict['id'])

        if share_names:
            LOG.debug('Creating CG snapshot %s.', snapshot_name)
            vserver_client.create_cg_snapshot(share_names, snapshot_name)

        return None, None

    @na_utils.trace
    def delete_cgsnapshot(self, context, snap_dict, share_server=None):
        """Deletes a consistency group snapshot."""
        try:
            vserver, vserver_client = self._get_vserver(
                share_server=share_server)
        except (exception.InvalidInput,
                exception.VserverNotSpecified,
                exception.VserverNotFound) as error:
            LOG.warning(_LW("Could not determine share server for CG snapshot "
                            "being deleted: %(snap)s. Deletion of CG snapshot "
                            "record will proceed anyway. Error: %(error)s"),
                        {'snap': snap_dict['id'], 'error': error})
            return None, None

        share_names = [self._get_valid_share_name(member['share_id'])
                       for member in snap_dict.get('cgsnapshot_members', [])]
        snapshot_name = self._get_valid_cg_snapshot_name(snap_dict['id'])

        for share_name in share_names:
            try:
                self._handle_busy_snapshot(vserver_client, share_name,
                                           snapshot_name)
            except exception.SnapshotNotFound:
                LOG.info(_LI("Snapshot %(snap)s does not exist for share "
                             "%(share)s."),
                         {'snap': snapshot_name, 'share': share_name})
                continue

            LOG.debug("Deleting snapshot %(snap)s for share %(share)s.",
                      {'snap': snapshot_name, 'share': share_name})
            vserver_client.delete_snapshot(share_name, snapshot_name)

        return None, None

    @na_utils.trace
    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_valid_share_name(share['id'])
        LOG.debug('Extending share %(name)s to %(size)s GB.',
                  {'name': share_name, 'size': new_size})
        vserver_client.set_volume_size(share_name, new_size)

    @na_utils.trace
    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_valid_share_name(share['id'])
        LOG.debug('Shrinking share %(name)s to %(size)s GB.',
                  {'name': share_name, 'size': new_size})
        vserver_client.set_volume_size(share_name, new_size)

    @na_utils.trace
    def allow_access(self, context, share, access, share_server=None):
        """Allows access to a given NAS storage."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_valid_share_name(share['id'])
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        helper.allow_access(context, share, share_name, access)

    @na_utils.trace
    def deny_access(self, context, share, access, share_server=None):
        """Denies access to a given NAS storage."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_valid_share_name(share['id'])
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        helper.deny_access(context, share, share_name, access)

    def setup_server(self, network_info, metadata=None):
        raise NotImplementedError()

    def teardown_server(self, server_details, security_services=None):
        raise NotImplementedError()

    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        raise NotImplementedError()

    @na_utils.trace
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

    @na_utils.trace
    def _update_ssc_aggr_info(self, aggregate_names, ssc_stats):
        """Updates the given SSC dictionary with new disk type information.

        :param aggregate_names: The aggregates this driver cares about
        :param ssc_stats: The dictionary to update
        """

        if not self._have_cluster_creds:
            return

        raid_types = self._client.get_aggregate_raid_types(aggregate_names)
        for aggregate_name, raid_type in six.iteritems(raid_types):
            ssc_stats[aggregate_name]['netapp_raid_type'] = raid_type

        disk_types = self._client.get_aggregate_disk_types(aggregate_names)
        for aggregate_name, disk_type in six.iteritems(disk_types):
            ssc_stats[aggregate_name]['netapp_disk_type'] = disk_type
