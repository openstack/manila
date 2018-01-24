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
import datetime
import json
import math
import socket

from oslo_config import cfg
from oslo_log import log
from oslo_service import loopingcall
from oslo_utils import timeutils
from oslo_utils import units
import six

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.cluster_mode import data_motion
from manila.share.drivers.netapp.dataontap.cluster_mode import performance
from manila.share.drivers.netapp.dataontap.protocols import cifs_cmode
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila.share.drivers.netapp import options as na_opts
from manila.share.drivers.netapp import utils as na_utils
from manila.share import share_types
from manila.share import utils as share_utils
from manila import utils as manila_utils

LOG = log.getLogger(__name__)
CONF = cfg.CONF


class NetAppCmodeFileStorageLibrary(object):

    AUTOSUPPORT_INTERVAL_SECONDS = 3600  # hourly
    SSC_UPDATE_INTERVAL_SECONDS = 3600  # hourly
    HOUSEKEEPING_INTERVAL_SECONDS = 600  # ten minutes

    SUPPORTED_PROTOCOLS = ('nfs', 'cifs')

    DEFAULT_FILTER_FUNCTION = 'capabilities.utilization < 70'
    DEFAULT_GOODNESS_FUNCTION = '100 - capabilities.utilization'

    # Maps NetApp qualified extra specs keys to corresponding backend API
    # client library argument keywords.  When we expose more backend
    # capabilities here, we will add them to this map.
    BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP = {
        'netapp:thin_provisioned': 'thin_provisioned',
        'netapp:dedup': 'dedup_enabled',
        'netapp:compression': 'compression_enabled',
        'netapp:split_clone_on_create': 'split',
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

    QOS_SPECS = {
        'netapp:maxiops': 'maxiops',
        'netapp:maxiopspergib': 'maxiopspergib',
        'netapp:maxbps': 'maxbps',
        'netapp:maxbpspergib': 'maxbpspergib',
    }

    SIZE_DEPENDENT_QOS_SPECS = {'maxiopspergib', 'maxbpspergib'}

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
        self.configuration.append_config_values(
            na_opts.netapp_data_motion_opts)

        self._licenses = []
        self._client = None
        self._clients = {}
        self._ssc_stats = {}
        self._have_cluster_creds = None
        self._cluster_info = {}

        self._app_version = kwargs.get('app_version', 'unknown')

        na_utils.setup_tracing(self.configuration.netapp_trace_flags,
                               self.configuration.netapp_api_trace_pattern)
        self._backend_name = self.configuration.safe_get(
            'share_backend_name') or driver_name

    @na_utils.trace
    def do_setup(self, context):
        self._client = self._get_api_client()
        self._have_cluster_creds = self._client.check_for_cluster_credentials()
        if self._have_cluster_creds is True:
            self._set_cluster_info()

        # Performance monitoring library
        self._perf_library = performance.PerformanceLibrary(self._client)

    @na_utils.trace
    def _set_cluster_info(self):
        self._cluster_info['nve_support'] = (
            self._client.is_nve_supported()
            and self._client.features.FLEXVOL_ENCRYPTION)

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
                trace=na_utils.TRACE_API,
                api_trace_pattern=na_utils.API_TRACE_PATTERN)
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
        LOG.info('Available licenses on %(backend)s '
                 'are %(licenses)s.', log_data)

        if 'nfs' not in self._licenses and 'cifs' not in self._licenses:
            msg = 'Neither NFS nor CIFS is licensed on %(backend)s'
            msg_args = {'backend': self._backend_name}
            LOG.error(msg, msg_args)

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

    def _get_backend_share_name(self, share_id):
        """Get share name according to share name template."""
        return self.configuration.netapp_volume_name_template % {
            'share_id': share_id.replace('-', '_')}

    def _get_backend_snapshot_name(self, snapshot_id):
        """Get snapshot name according to snapshot name template."""
        return 'share_snapshot_' + snapshot_id.replace('-', '_')

    def _get_backend_cg_snapshot_name(self, snapshot_id):
        """Get snapshot name according to snapshot name template."""
        return 'share_cg_snapshot_' + snapshot_id.replace('-', '_')

    def _get_backend_qos_policy_group_name(self, share_id):
        """Get QoS policy name according to QoS policy group name template."""
        return self.configuration.netapp_qos_policy_group_name_template % {
            'share_id': share_id.replace('-', '_')}

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

    def get_default_filter_function(self):
        """Get the default filter_function string."""
        return self.DEFAULT_FILTER_FUNCTION

    def get_default_goodness_function(self):
        """Get the default goodness_function string."""
        return self.DEFAULT_GOODNESS_FUNCTION

    @na_utils.trace
    def get_share_stats(self, filter_function=None, goodness_function=None):
        """Retrieve stats info from Data ONTAP backend."""

        data = {
            'share_backend_name': self._backend_name,
            'driver_name': self.driver_name,
            'vendor_name': 'NetApp',
            'driver_version': '1.0',
            'netapp_storage_family': 'ontap_cluster',
            'storage_protocol': 'NFS_CIFS',
            'pools': self._get_pools(filter_function=filter_function,
                                     goodness_function=goodness_function),
            'share_group_stats': {
                'consistent_snapshot_support': 'host',
            },
        }

        if (self.configuration.replication_domain and
                not self.configuration.driver_handles_share_servers):
            data['replication_type'] = 'dr'
            data['replication_domain'] = self.configuration.replication_domain

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
    def _get_pools(self, filter_function=None, goodness_function=None):
        """Retrieve list of pools available to this backend."""

        pools = []
        aggr_space = self._get_aggregate_space()
        aggregates = aggr_space.keys()

        if self._have_cluster_creds:
            # Get up-to-date node utilization metrics just once.
            self._perf_library.update_performance_cache({}, self._ssc_stats)
            qos_support = True
        else:
            qos_support = False

        netapp_flexvol_encryption = self._cluster_info.get(
            'nve_support', False)

        for aggr_name in sorted(aggregates):

            reserved_percentage = self.configuration.reserved_share_percentage

            total_capacity_gb = na_utils.round_down(float(
                aggr_space[aggr_name].get('total', 0)) / units.Gi)
            free_capacity_gb = na_utils.round_down(float(
                aggr_space[aggr_name].get('available', 0)) / units.Gi)
            allocated_capacity_gb = na_utils.round_down(float(
                aggr_space[aggr_name].get('used', 0)) / units.Gi)

            if total_capacity_gb == 0.0:
                total_capacity_gb = 'unknown'

            pool = {
                'pool_name': aggr_name,
                'filter_function': filter_function,
                'goodness_function': goodness_function,
                'total_capacity_gb': total_capacity_gb,
                'free_capacity_gb': free_capacity_gb,
                'allocated_capacity_gb': allocated_capacity_gb,
                'qos': qos_support,
                'reserved_percentage': reserved_percentage,
                'dedupe': [True, False],
                'compression': [True, False],
                'netapp_flexvol_encryption': netapp_flexvol_encryption,
                'thin_provisioning': [True, False],
                'snapshot_support': True,
                'create_share_from_snapshot_support': True,
                'revert_to_snapshot_support': True,
            }

            # Add storage service catalog data.
            pool_ssc_stats = self._ssc_stats.get(aggr_name)
            if pool_ssc_stats:
                pool.update(pool_ssc_stats)

            # Add utilization info, or nominal value if not available.
            utilization = self._perf_library.get_node_utilization_for_pool(
                aggr_name)
            pool['utilization'] = na_utils.round_down(utilization)

            pools.append(pool)

        return pools

    @na_utils.trace
    def _handle_ems_logging(self):
        """Build and send an EMS log message."""
        self._client.send_ems_log_message(self._build_ems_log_message_0())
        self._client.send_ems_log_message(self._build_ems_log_message_1())

    def _build_base_ems_log_message(self):
        """Construct EMS Autosupport log message common to all events."""

        ems_log = {
            'computer-name': socket.gethostname() or 'Manila_node',
            'event-source': 'Manila driver %s' % self.driver_name,
            'app-version': self._app_version,
            'category': 'provisioning',
            'log-level': '5',
            'auto-support': 'false',
        }
        return ems_log

    @na_utils.trace
    def _build_ems_log_message_0(self):
        """Construct EMS Autosupport log message with deployment info."""

        ems_log = self._build_base_ems_log_message()
        ems_log.update({
            'event-id': '0',
            'event-description': 'OpenStack Manila connected to cluster node',
        })
        return ems_log

    @na_utils.trace
    def _build_ems_log_message_1(self):
        """Construct EMS Autosupport log message with storage pool info."""

        message = self._get_ems_pool_info()

        ems_log = self._build_base_ems_log_message()
        ems_log.update({
            'event-id': '1',
            'event-description': json.dumps(message),
        })
        return ems_log

    def _get_ems_pool_info(self):
        raise NotImplementedError()

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

        share_name = self._get_backend_share_name(share['id'])
        return self._client.get_aggregate_for_volume(share_name)

    @na_utils.trace
    def create_share(self, context, share, share_server):
        """Creates new share."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        self._allocate_container(share, vserver, vserver_client)
        return self._create_export(share, share_server, vserver,
                                   vserver_client)

    @na_utils.trace
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Creates new share from snapshot."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        self._allocate_container_from_snapshot(
            share, snapshot, vserver, vserver_client)
        return self._create_export(share, share_server, vserver,
                                   vserver_client)

    @na_utils.trace
    def _allocate_container(self, share, vserver, vserver_client,
                            replica=False):
        """Create new share on aggregate."""
        share_name = self._get_backend_share_name(share['id'])

        # Get Data ONTAP aggregate name as pool name.
        pool_name = share_utils.extract_host(share['host'], level='pool')
        if pool_name is None:
            msg = _("Pool is not available in the share host field.")
            raise exception.InvalidHost(reason=msg)

        provisioning_options = self._get_provisioning_options_for_share(
            share, vserver, replica=replica)

        if replica:
            # If this volume is intended to be a replication destination,
            # create it as the 'data-protection' type
            provisioning_options['volume_type'] = 'dp'

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

    def _get_normalized_qos_specs(self, extra_specs):
        if not extra_specs.get('qos'):
            return {}

        normalized_qos_specs = {
            self.QOS_SPECS[key.lower()]: value
            for key, value in extra_specs.items()
            if self.QOS_SPECS.get(key.lower())
        }
        if not normalized_qos_specs:
            msg = _("The extra-spec 'qos' is set to True, but no netapp "
                    "supported qos-specs have been specified in the share "
                    "type. Cannot provision a QoS policy. Specify any of the "
                    "following extra-specs and try again: %s")
            raise exception.NetAppException(msg % list(self.QOS_SPECS))

        # TODO(gouthamr): Modify check when throughput floors are allowed
        if len(normalized_qos_specs) > 1:
            msg = _('Only one NetApp QoS spec can be set at a time. '
                    'Specified QoS limits: %s')
            raise exception.NetAppException(msg % normalized_qos_specs)

        return normalized_qos_specs

    def _get_max_throughput(self, share_size, qos_specs):
        # QoS limits are exclusive of one another.
        if 'maxiops' in qos_specs:
            return '%siops' % qos_specs['maxiops']
        elif 'maxiopspergib' in qos_specs:
            return '%siops' % six.text_type(
                int(qos_specs['maxiopspergib']) * int(share_size))
        elif 'maxbps' in qos_specs:
            return '%sB/s' % qos_specs['maxbps']
        elif 'maxbpspergib' in qos_specs:
            return '%sB/s' % six.text_type(
                int(qos_specs['maxbpspergib']) * int(share_size))

    @na_utils.trace
    def _create_qos_policy_group(self, share, vserver, qos_specs):
        max_throughput = self._get_max_throughput(share['size'], qos_specs)
        qos_policy_group_name = self._get_backend_qos_policy_group_name(
            share['id'])
        self._client.qos_policy_group_create(qos_policy_group_name, vserver,
                                             max_throughput=max_throughput)
        return qos_policy_group_name

    @na_utils.trace
    def _get_provisioning_options_for_share(self, share, vserver,
                                            replica=False):
        """Return provisioning options from a share.

        Starting with a share, this method gets the extra specs, rationalizes
        NetApp vs. standard extra spec values, ensures their validity, and
        returns them in a form suitable for passing to various API client
        methods.
        """
        extra_specs = share_types.get_extra_specs_from_share(share)
        extra_specs = self._remap_standard_boolean_extra_specs(extra_specs)
        self._check_extra_specs_validity(share, extra_specs)
        provisioning_options = self._get_provisioning_options(extra_specs)
        qos_specs = self._get_normalized_qos_specs(extra_specs)
        if qos_specs and not replica:
            qos_policy_group = self._create_qos_policy_group(
                share, vserver, qos_specs)
            provisioning_options['qos_policy_group'] = qos_policy_group
        return provisioning_options

    @na_utils.trace
    def _get_provisioning_options(self, specs):
        """Return a merged result of string and binary provisioning options."""
        boolean_args = self._get_boolean_provisioning_options(
            specs, self.BOOLEAN_QUALIFIED_EXTRA_SPECS_MAP)

        string_args = self._get_string_provisioning_options(
            specs, self.STRING_QUALIFIED_EXTRA_SPECS_MAP)
        result = boolean_args.copy()
        result.update(string_args)

        result['encrypt'] = self._get_nve_option(specs)

        return result

    def _get_nve_option(self, specs):
        if 'netapp_flexvol_encryption' in specs:
            nve = specs['netapp_flexvol_encryption'].lower() == 'true'
        else:
            nve = False

        return nve

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
            self, share, snapshot, vserver, vserver_client,
            snapshot_name_func=_get_backend_snapshot_name):
        """Clones existing share."""
        share_name = self._get_backend_share_name(share['id'])
        parent_share_name = self._get_backend_share_name(snapshot['share_id'])
        if snapshot.get('provider_location') is None:
            parent_snapshot_name = snapshot_name_func(self, snapshot['id'])
        else:
            parent_snapshot_name = snapshot['provider_location']

        provisioning_options = self._get_provisioning_options_for_share(
            share, vserver)

        LOG.debug('Creating share from snapshot %s', snapshot['id'])
        vserver_client.create_volume_clone(share_name, parent_share_name,
                                           parent_snapshot_name,
                                           **provisioning_options)
        if share['size'] > snapshot['size']:
            vserver_client.set_volume_size(share_name, share['size'])

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
            LOG.warning("Could not determine share server for share being "
                        "deleted: %(share)s. Deletion of share record "
                        "will proceed anyway. Error: %(error)s",
                        {'share': share['id'], 'error': error})
            return

        share_name = self._get_backend_share_name(share['id'])
        if self._share_exists(share_name, vserver_client):
            self._remove_export(share, vserver_client)
            self._deallocate_container(share_name, vserver_client)
            qos_policy_for_share = self._get_backend_qos_policy_group_name(
                share['id'])
            self._client.mark_qos_policy_group_for_deletion(
                qos_policy_for_share)
        else:
            LOG.info("Share %s does not exist.", share['id'])

    @na_utils.trace
    def _deallocate_container(self, share_name, vserver_client):
        """Free share space."""
        vserver_client.unmount_volume(share_name, force=True)
        vserver_client.offline_volume(share_name)
        vserver_client.delete_volume(share_name)

    @na_utils.trace
    def _create_export(self, share, share_server, vserver, vserver_client,
                       clear_current_export_policy=True):
        """Creates NAS storage."""
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        share_name = self._get_backend_share_name(share['id'])

        interfaces = vserver_client.get_network_interfaces(
            protocols=[share['share_proto']])

        if not interfaces:
            msg = _('Cannot find network interfaces for Vserver %(vserver)s '
                    'and protocol %(proto)s.')
            msg_args = {'vserver': vserver, 'proto': share['share_proto']}
            raise exception.NetAppException(msg % msg_args)

        # Get LIF addresses with metadata
        export_addresses = self._get_export_addresses_with_metadata(
            share, share_server, interfaces)

        # Create the share and get a callback for generating export locations
        callback = helper.create_share(
            share, share_name,
            clear_current_export_policy=clear_current_export_policy)

        # Generate export locations using addresses, metadata and callback
        export_locations = [
            {
                'path': callback(export_address),
                'is_admin_only': metadata.pop('is_admin_only', False),
                'metadata': metadata,
            }
            for export_address, metadata
            in copy.deepcopy(export_addresses).items()
        ]

        # Sort the export locations to report preferred paths first
        export_locations = self._sort_export_locations_by_preferred_paths(
            export_locations)

        return export_locations

    @na_utils.trace
    def _get_export_addresses_with_metadata(self, share, share_server,
                                            interfaces):
        """Return interface addresses with locality and other metadata."""

        # Get home node so we can identify preferred paths
        aggregate_name = share_utils.extract_host(share['host'], level='pool')
        home_node = self._get_aggregate_node(aggregate_name)

        # Get admin LIF addresses so we can identify admin export locations
        admin_addresses = self._get_admin_addresses_for_share_server(
            share_server)

        addresses = {}
        for interface in interfaces:

            address = interface['address']
            is_admin_only = address in admin_addresses

            if home_node:
                preferred = interface.get('home-node') == home_node
            else:
                preferred = False

            addresses[address] = {
                'is_admin_only': is_admin_only,
                'preferred': preferred,
            }

        return addresses

    @na_utils.trace
    def _get_admin_addresses_for_share_server(self, share_server):

        if not share_server:
            return []

        admin_addresses = []
        for network_allocation in share_server.get('network_allocations'):
            if network_allocation['label'] == 'admin':
                admin_addresses.append(network_allocation['ip_address'])

        return admin_addresses

    @na_utils.trace
    def _sort_export_locations_by_preferred_paths(self, export_locations):
        """Sort the export locations to report preferred paths first."""

        sort_key = lambda location: location.get(
            'metadata', {}).get('preferred') is not True

        return sorted(export_locations, key=sort_key)

    @na_utils.trace
    def _remove_export(self, share, vserver_client):
        """Deletes NAS storage."""
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        share_name = self._get_backend_share_name(share['id'])
        target = helper.get_target(share)
        # Share may be in error state, so there's no share and target.
        if target:
            helper.delete_share(share, share_name)

    @na_utils.trace
    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of a share."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_backend_share_name(snapshot['share_id'])
        snapshot_name = self._get_backend_snapshot_name(snapshot['id'])
        LOG.debug('Creating snapshot %s', snapshot_name)
        vserver_client.create_snapshot(share_name, snapshot_name)
        return {'provider_location': snapshot_name}

    def revert_to_snapshot(self, context, snapshot, share_server=None):
        """Reverts a share (in place) to the specified snapshot."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_backend_share_name(snapshot['share_id'])
        snapshot_name = (snapshot.get('provider_location') or
                         self._get_backend_snapshot_name(snapshot['id']))
        LOG.debug('Restoring snapshot %s', snapshot_name)
        vserver_client.restore_snapshot(share_name, snapshot_name)

    @na_utils.trace
    def delete_snapshot(self, context, snapshot, share_server=None,
                        snapshot_name=None):
        """Deletes a snapshot of a share."""
        try:
            vserver, vserver_client = self._get_vserver(
                share_server=share_server)
        except (exception.InvalidInput,
                exception.VserverNotSpecified,
                exception.VserverNotFound) as error:
            LOG.warning("Could not determine share server for snapshot "
                        "being deleted: %(snap)s. Deletion of snapshot "
                        "record will proceed anyway. Error: %(error)s",
                        {'snap': snapshot['id'], 'error': error})
            return

        share_name = self._get_backend_share_name(snapshot['share_id'])
        snapshot_name = (snapshot.get('provider_location') or snapshot_name or
                         self._get_backend_snapshot_name(snapshot['id']))

        try:
            self._delete_snapshot(vserver_client, share_name, snapshot_name)
        except exception.SnapshotResourceNotFound:
            msg = ("Snapshot %(snap)s does not exist on share %(share)s.")
            msg_args = {'snap': snapshot_name, 'share': share_name}
            LOG.info(msg, msg_args)

    def _delete_snapshot(self, vserver_client, share_name, snapshot_name):
        """Deletes a backend snapshot, handling busy snapshots as needed."""

        backend_snapshot = vserver_client.get_snapshot(share_name,
                                                       snapshot_name)

        LOG.debug('Deleting snapshot %(snap)s for share %(share)s.',
                  {'snap': snapshot_name, 'share': share_name})

        if not backend_snapshot['busy']:
            vserver_client.delete_snapshot(share_name, snapshot_name)

        elif backend_snapshot['owners'] == {'volume clone'}:
            # Snapshots are locked by clone(s), so split clone and soft delete
            snapshot_children = vserver_client.get_clone_children_for_snapshot(
                share_name, snapshot_name)
            for snapshot_child in snapshot_children:
                vserver_client.split_volume_clone(snapshot_child['name'])

            vserver_client.soft_delete_snapshot(share_name, snapshot_name)

        else:
            raise exception.ShareSnapshotIsBusy(snapshot_name=snapshot_name)

    @na_utils.trace
    def manage_existing(self, share, driver_options):
        vserver, vserver_client = self._get_vserver(share_server=None)
        share_size = self._manage_container(share, vserver, vserver_client)
        export_locations = self._create_export(share, None, vserver,
                                               vserver_client)
        return {'size': share_size, 'export_locations': export_locations}

    @na_utils.trace
    def unmanage(self, share):
        pass

    @na_utils.trace
    def _manage_container(self, share, vserver, vserver_client):
        """Bring existing volume under management as a share."""

        protocol_helper = self._get_helper(share)
        protocol_helper.set_client(vserver_client)

        volume_name = protocol_helper.get_share_name_for_share(share)
        if not volume_name:
            msg = _('Volume could not be determined from export location '
                    '%(export)s.')
            msg_args = {'export': share['export_location']}
            raise exception.ManageInvalidShare(reason=msg % msg_args)

        share_name = self._get_backend_share_name(share['id'])
        aggregate_name = share_utils.extract_host(share['host'], level='pool')

        # Get existing volume info
        volume = vserver_client.get_volume_to_manage(aggregate_name,
                                                     volume_name)

        if not volume:
            msg = _('Volume %(volume)s not found on aggregate %(aggr)s.')
            msg_args = {'volume': volume_name, 'aggr': aggregate_name}
            raise exception.ManageInvalidShare(reason=msg % msg_args)

        # When calculating the size, round up to the next GB.
        volume_size = int(math.ceil(float(volume['size']) / units.Gi))

        # Validate extra specs
        extra_specs = share_types.get_extra_specs_from_share(share)
        try:
            self._check_extra_specs_validity(share, extra_specs)
            self._check_aggregate_extra_specs_validity(aggregate_name,
                                                       extra_specs)
        except exception.ManilaException as ex:
            raise exception.ManageExistingShareTypeMismatch(
                reason=six.text_type(ex))

        # Ensure volume is manageable
        self._validate_volume_for_manage(volume, vserver_client)

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

        qos_policy_group_name = self._modify_or_create_qos_for_existing_share(
            share, extra_specs, vserver, vserver_client)
        if qos_policy_group_name:
            provisioning_options['qos_policy_group'] = qos_policy_group_name

        # Modify volume to match extra specs
        vserver_client.modify_volume(aggregate_name, share_name,
                                     **provisioning_options)

        # Save original volume info to private storage
        original_data = {
            'original_name': volume['name'],
            'original_junction_path': volume['junction-path']
        }
        self.private_storage.update(share['id'], original_data)

        return volume_size

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

        if vserver_client.volume_has_snapmirror_relationships(volume):
            msg = _('Volume %(volume)s must not be in any snapmirror '
                    'relationships.')
            msg_args = {'volume': volume['name']}
            raise exception.ManageInvalidShare(reason=msg % msg_args)

    @na_utils.trace
    def manage_existing_snapshot(self, snapshot, driver_options):
        """Brings an existing snapshot under Manila management."""
        vserver, vserver_client = self._get_vserver(share_server=None)
        share_name = self._get_backend_share_name(snapshot['share_id'])
        existing_snapshot_name = snapshot.get('provider_location')
        new_snapshot_name = self._get_backend_snapshot_name(snapshot['id'])

        if not existing_snapshot_name:
            msg = _('provider_location not specified.')
            raise exception.ManageInvalidShareSnapshot(reason=msg)

        # Get the volume containing the snapshot so we can report its size
        try:
            volume = vserver_client.get_volume(share_name)
        except (netapp_api.NaApiError,
                exception.StorageResourceNotFound,
                exception.NetAppException):
            msg = _('Could not determine snapshot %(snap)s size from '
                    'volume %(vol)s.')
            msg_args = {'snap': existing_snapshot_name, 'vol': share_name}
            LOG.exception(msg, msg_args)
            raise exception.ShareNotFound(share_id=snapshot['share_id'])

        # Ensure there aren't any mirrors on this volume
        if vserver_client.volume_has_snapmirror_relationships(volume):
            msg = _('Share %s has SnapMirror relationships.')
            msg_args = {'vol': share_name}
            raise exception.ManageInvalidShareSnapshot(reason=msg % msg_args)

        # Rename snapshot
        try:
            vserver_client.rename_snapshot(share_name,
                                           existing_snapshot_name,
                                           new_snapshot_name)
        except netapp_api.NaApiError:
            msg = _('Could not rename snapshot %(snap)s in share %(vol)s.')
            msg_args = {'snap': existing_snapshot_name, 'vol': share_name}
            raise exception.ManageInvalidShareSnapshot(reason=msg % msg_args)

        # Save original snapshot info to private storage
        original_data = {'original_name': existing_snapshot_name}
        self.private_storage.update(snapshot['id'], original_data)

        # When calculating the size, round up to the next GB.
        size = int(math.ceil(float(volume['size']) / units.Gi))

        return {'size': size, 'provider_location': new_snapshot_name}

    @na_utils.trace
    def unmanage_snapshot(self, snapshot):
        """Removes the specified snapshot from Manila management."""

    @na_utils.trace
    def create_consistency_group_from_cgsnapshot(
            self, context, cg_dict, cgsnapshot_dict, share_server=None):
        """Creates a consistency group from an existing CG snapshot."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)

        # Ensure there is something to do
        if not cgsnapshot_dict['share_group_snapshot_members']:
            return None, None

        clone_list = self._collate_cg_snapshot_info(cg_dict, cgsnapshot_dict)
        share_update_list = []

        LOG.debug('Creating consistency group from CG snapshot %s.',
                  cgsnapshot_dict['id'])

        for clone in clone_list:

            self._allocate_container_from_snapshot(
                clone['share'], clone['snapshot'], vserver, vserver_client,
                NetAppCmodeFileStorageLibrary._get_backend_cg_snapshot_name)

            export_locations = self._create_export(clone['share'],
                                                   share_server,
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

            for cgsnapshot_member in (
                    cgsnapshot_dict['share_group_snapshot_members']):
                if (share['source_share_group_snapshot_member_id'] ==
                        cgsnapshot_member['id']):
                    clone_info['snapshot'] = {
                        'share_id': cgsnapshot_member['share_id'],
                        'id': cgsnapshot_dict['id'],
                        'size': cgsnapshot_member['size'],
                    }
                    break

            else:
                msg = _("Invalid data supplied for creating consistency group "
                        "from CG snapshot %s.") % cgsnapshot_dict['id']
                raise exception.InvalidShareGroup(reason=msg)

            clone_list.append(clone_info)

        return clone_list

    @na_utils.trace
    def create_cgsnapshot(self, context, snap_dict, share_server=None):
        """Creates a consistency group snapshot."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)

        share_names = [self._get_backend_share_name(member['share_id'])
                       for member in
                       snap_dict.get('share_group_snapshot_members', [])]
        snapshot_name = self._get_backend_cg_snapshot_name(snap_dict['id'])

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
            LOG.warning("Could not determine share server for CG snapshot "
                        "being deleted: %(snap)s. Deletion of CG snapshot "
                        "record will proceed anyway. Error: %(error)s",
                        {'snap': snap_dict['id'], 'error': error})
            return None, None

        share_names = [self._get_backend_share_name(member['share_id'])
                       for member in (
                           snap_dict.get('share_group_snapshot_members', []))]
        snapshot_name = self._get_backend_cg_snapshot_name(snap_dict['id'])

        for share_name in share_names:
            try:
                self._delete_snapshot(
                    vserver_client, share_name, snapshot_name)
            except exception.SnapshotResourceNotFound:
                msg = ("Snapshot %(snap)s does not exist on share "
                       "%(share)s.")
                msg_args = {'snap': snapshot_name, 'share': share_name}
                LOG.info(msg, msg_args)
                continue

        return None, None

    @staticmethod
    def _is_group_cg(context, share_group):
        return 'host' == share_group.consistent_snapshot_support

    @na_utils.trace
    def create_group_snapshot(self, context, snap_dict, fallback_create,
                              share_server=None):
        share_group = snap_dict['share_group']
        if self._is_group_cg(context, share_group):
            return self.create_cgsnapshot(context, snap_dict,
                                          share_server=share_server)
        else:
            return fallback_create(context, snap_dict,
                                   share_server=share_server)

    @na_utils.trace
    def delete_group_snapshot(self, context, snap_dict, fallback_delete,
                              share_server=None):
        share_group = snap_dict['share_group']
        if self._is_group_cg(context, share_group):
            return self.delete_cgsnapshot(context, snap_dict,
                                          share_server=share_server)
        else:
            return fallback_delete(context, snap_dict,
                                   share_server=share_server)

    @na_utils.trace
    def create_group_from_snapshot(self, context, share_group,
                                   snapshot_dict, fallback_create,
                                   share_server=None):
        share_group2 = snapshot_dict['share_group']
        if self._is_group_cg(context, share_group2):
            return self.create_consistency_group_from_cgsnapshot(
                context, share_group, snapshot_dict,
                share_server=share_server)
        else:
            return fallback_create(context, share_group, snapshot_dict,
                                   share_server=share_server)

    @na_utils.trace
    def _adjust_qos_policy_with_volume_resize(self, share, new_size,
                                              vserver_client):
        # Adjust QoS policy on a share if any
        if self._have_cluster_creds:
            share_name = self._get_backend_share_name(share['id'])
            share_on_the_backend = vserver_client.get_volume(share_name)
            qos_policy_on_share = share_on_the_backend['qos-policy-group-name']
            if qos_policy_on_share is None:
                return

            extra_specs = share_types.get_extra_specs_from_share(share)
            qos_specs = self._get_normalized_qos_specs(extra_specs)
            size_dependent_specs = {k: v for k, v in qos_specs.items() if k in
                                    self.SIZE_DEPENDENT_QOS_SPECS}
            if size_dependent_specs:
                max_throughput = self._get_max_throughput(
                    new_size, size_dependent_specs)
                self._client.qos_policy_group_modify(
                    qos_policy_on_share, max_throughput)

    @na_utils.trace
    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_backend_share_name(share['id'])
        LOG.debug('Extending share %(name)s to %(size)s GB.',
                  {'name': share_name, 'size': new_size})
        vserver_client.set_volume_size(share_name, new_size)
        self._adjust_qos_policy_with_volume_resize(share, new_size,
                                                   vserver_client)

    @na_utils.trace
    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_backend_share_name(share['id'])
        LOG.debug('Shrinking share %(name)s to %(size)s GB.',
                  {'name': share_name, 'size': new_size})
        vserver_client.set_volume_size(share_name, new_size)
        self._adjust_qos_policy_with_volume_resize(share, new_size,
                                                   vserver_client)

    @na_utils.trace
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Updates access rules for a share."""
        # NOTE(ameade): We do not need to add export rules to a non-active
        # replica as it will fail.
        replica_state = share.get('replica_state')
        if (replica_state is not None and
                replica_state != constants.REPLICA_STATE_ACTIVE):
            return
        try:
            vserver, vserver_client = self._get_vserver(
                share_server=share_server)
        except (exception.InvalidInput,
                exception.VserverNotSpecified,
                exception.VserverNotFound) as error:
            LOG.warning("Could not determine share server for share "
                        "%(share)s during access rules update. "
                        "Error: %(error)s",
                        {'share': share['id'], 'error': error})
            return

        share_name = self._get_backend_share_name(share['id'])
        if self._share_exists(share_name, vserver_client):
            helper = self._get_helper(share)
            helper.set_client(vserver_client)
            helper.update_access(share, share_name, access_rules)
        else:
            raise exception.ShareResourceNotFound(share_id=share['id'])

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
        LOG.info("Updating storage service catalog information for "
                 "backend '%s'", self._backend_name)

        # Work on a copy and update the ssc data atomically before returning.
        ssc_stats = copy.deepcopy(self._ssc_stats)

        aggregate_names = self._find_matching_aggregates()

        # Initialize entries for each aggregate.
        for aggregate_name in aggregate_names:
            if aggregate_name not in ssc_stats:
                ssc_stats[aggregate_name] = {
                    'netapp_aggregate': aggregate_name,
                }

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

        for aggregate_name in aggregate_names:

            aggregate = self._client.get_aggregate(aggregate_name)
            hybrid = (six.text_type(aggregate.get('is-hybrid')).lower()
                      if 'is-hybrid' in aggregate else None)
            disk_types = self._client.get_aggregate_disk_types(aggregate_name)

            ssc_stats[aggregate_name].update({
                'netapp_raid_type': aggregate.get('raid-type'),
                'netapp_hybrid_aggregate': hybrid,
                'netapp_disk_type': disk_types,
            })

    def _find_active_replica(self, replica_list):
        # NOTE(ameade): Find current active replica. There can only be one
        # active replica (SnapMirror source volume) at a time in cDOT.
        for r in replica_list:
            if r['replica_state'] == constants.REPLICA_STATE_ACTIVE:
                return r

    def _find_nonactive_replicas(self, replica_list):
        """Returns a list of all except the active replica."""
        return [replica for replica in replica_list
                if replica['replica_state'] != constants.REPLICA_STATE_ACTIVE]

    def create_replica(self, context, replica_list, new_replica,
                       access_rules, share_snapshots, share_server=None):
        """Creates the new replica on this backend and sets up SnapMirror."""
        active_replica = self._find_active_replica(replica_list)
        dm_session = data_motion.DataMotionSession()

        # 1. Create the destination share
        dest_backend = share_utils.extract_host(new_replica['host'],
                                                level='backend_name')

        vserver = (dm_session.get_vserver_from_share(new_replica) or
                   self.configuration.netapp_vserver)

        vserver_client = data_motion.get_client_for_backend(
            dest_backend, vserver_name=vserver)

        self._allocate_container(new_replica, vserver, vserver_client,
                                 replica=True)

        # 2. Setup SnapMirror
        dm_session.create_snapmirror(active_replica, new_replica)

        model_update = {
            'export_locations': [],
            'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC,
            'access_rules_status': constants.STATUS_ACTIVE,
        }

        return model_update

    def delete_replica(self, context, replica_list, replica, share_snapshots,
                       share_server=None):
        """Removes the replica on this backend and destroys SnapMirror."""
        dm_session = data_motion.DataMotionSession()
        # 1. Remove SnapMirror
        dest_backend = share_utils.extract_host(replica['host'],
                                                level='backend_name')
        vserver = (dm_session.get_vserver_from_share(replica) or
                   self.configuration.netapp_vserver)

        # Ensure that all potential snapmirror relationships and their metadata
        # involving the replica are destroyed.
        for other_replica in replica_list:
            if other_replica['id'] != replica['id']:
                dm_session.delete_snapmirror(other_replica, replica)
                dm_session.delete_snapmirror(replica, other_replica)

        # 2. Delete share
        vserver_client = data_motion.get_client_for_backend(
            dest_backend, vserver_name=vserver)
        share_name = self._get_backend_share_name(replica['id'])
        if self._share_exists(share_name, vserver_client):
            self._deallocate_container(share_name, vserver_client)

    def update_replica_state(self, context, replica_list, replica,
                             access_rules, share_snapshots, share_server=None):
        """Returns the status of the given replica on this backend."""
        active_replica = self._find_active_replica(replica_list)

        share_name = self._get_backend_share_name(replica['id'])
        vserver, vserver_client = self._get_vserver(share_server=share_server)

        if not vserver_client.volume_exists(share_name):
            msg = _("Volume %(share_name)s does not exist on vserver "
                    "%(vserver)s.")
            msg_args = {'share_name': share_name, 'vserver': vserver}
            raise exception.ShareResourceNotFound(msg % msg_args)

        # NOTE(cknight): The SnapMirror may have been intentionally broken by
        # a revert-to-snapshot operation, in which case this method should not
        # attempt to change anything.
        if active_replica['status'] == constants.STATUS_REVERTING:
            return None

        dm_session = data_motion.DataMotionSession()
        try:
            snapmirrors = dm_session.get_snapmirrors(active_replica, replica)
        except netapp_api.NaApiError:
            LOG.exception("Could not get snapmirrors for replica %s.",
                          replica['id'])
            return constants.STATUS_ERROR

        if not snapmirrors:
            if replica['status'] != constants.STATUS_CREATING:
                try:
                    dm_session.create_snapmirror(active_replica, replica)
                except netapp_api.NaApiError:
                    LOG.exception("Could not create snapmirror for "
                                  "replica %s.", replica['id'])
                    return constants.STATUS_ERROR
            return constants.REPLICA_STATE_OUT_OF_SYNC

        snapmirror = snapmirrors[0]

        if (snapmirror.get('mirror-state') != 'snapmirrored' and
                snapmirror.get('relationship-status') == 'transferring'):
            return constants.REPLICA_STATE_OUT_OF_SYNC

        if snapmirror.get('mirror-state') != 'snapmirrored':
            try:
                vserver_client.resume_snapmirror(snapmirror['source-vserver'],
                                                 snapmirror['source-volume'],
                                                 vserver,
                                                 share_name)
                vserver_client.resync_snapmirror(snapmirror['source-vserver'],
                                                 snapmirror['source-volume'],
                                                 vserver,
                                                 share_name)
                return constants.REPLICA_STATE_OUT_OF_SYNC
            except netapp_api.NaApiError:
                LOG.exception("Could not resync snapmirror.")
                return constants.STATUS_ERROR

        last_update_timestamp = float(
            snapmirror.get('last-transfer-end-timestamp', 0))
        # TODO(ameade): Have a configurable RPO for replicas, for now it is
        # one hour.
        if (last_update_timestamp and
            (timeutils.is_older_than(
                datetime.datetime.utcfromtimestamp(last_update_timestamp)
                .isoformat(), 3600))):
            return constants.REPLICA_STATE_OUT_OF_SYNC

        # Check all snapshots exist
        snapshots = [snap['share_replica_snapshot']
                     for snap in share_snapshots]
        for snap in snapshots:
            snapshot_name = snap.get('provider_location')
            if not vserver_client.snapshot_exists(snapshot_name, share_name):
                return constants.REPLICA_STATE_OUT_OF_SYNC

        return constants.REPLICA_STATE_IN_SYNC

    def promote_replica(self, context, replica_list, replica, access_rules,
                        share_server=None):
        """Switch SnapMirror relationships and allow r/w ops on replica.

        Creates a DataMotion session and switches the direction of the
        SnapMirror relationship between the currently 'active' instance (
        SnapMirror source volume) and the replica. Also attempts setting up
        SnapMirror relationships between the other replicas and the new
        SnapMirror source volume ('active' instance).
        :param context: Request Context
        :param replica_list: List of replicas, including the 'active' instance
        :param replica: Replica to promote to SnapMirror source
        :param access_rules: Access rules to apply to the replica
        :param share_server: ShareServer class instance of replica
        :return: Updated replica_list
        """
        orig_active_replica = self._find_active_replica(replica_list)

        dm_session = data_motion.DataMotionSession()

        new_replica_list = []

        # Setup the new active replica
        try:
            new_active_replica = (
                self._convert_destination_replica_to_independent(
                    context, dm_session, orig_active_replica, replica,
                    access_rules, share_server=share_server))
        except exception.StorageCommunicationException:
            LOG.exception("Could not communicate with the backend "
                          "for replica %s during promotion.",
                          replica['id'])
            new_active_replica = copy.deepcopy(replica)
            new_active_replica['replica_state'] = (
                constants.STATUS_ERROR)
            new_active_replica['status'] = constants.STATUS_ERROR
            return [new_active_replica]

        new_replica_list.append(new_active_replica)

        # Change the source replica for all destinations to the new
        # active replica.
        for r in replica_list:
            if r['id'] != replica['id']:
                r = self._safe_change_replica_source(dm_session, r,
                                                     orig_active_replica,
                                                     replica,
                                                     replica_list)
                new_replica_list.append(r)

        self._handle_qos_on_replication_change(dm_session,
                                               new_active_replica,
                                               orig_active_replica,
                                               share_server=share_server)

        return new_replica_list

    def _handle_qos_on_replication_change(self, dm_session, new_active_replica,
                                          orig_active_replica,
                                          share_server=None):
        # QoS operations: Remove and purge QoS policy on old active replica
        # if any and create a new policy on the destination if necessary.
        extra_specs = share_types.get_extra_specs_from_share(
            orig_active_replica)
        qos_specs = self._get_normalized_qos_specs(extra_specs)

        if qos_specs and self._have_cluster_creds:
            dm_session.remove_qos_on_old_active_replica(orig_active_replica)
            # Check if a QoS policy already exists for the promoted replica,
            # if it does, modify it as necessary, else create it:
            try:
                new_active_replica_qos_policy = (
                    self._get_backend_qos_policy_group_name(
                        new_active_replica['id']))
                vserver, vserver_client = self._get_vserver(
                    share_server=share_server)

                volume_name_on_backend = self._get_backend_share_name(
                    new_active_replica['id'])
                if not self._client.qos_policy_group_exists(
                        new_active_replica_qos_policy):
                    self._create_qos_policy_group(
                        new_active_replica, vserver, qos_specs)
                else:
                    max_throughput = self._get_max_throughput(
                        new_active_replica['size'], qos_specs)
                    self._client.qos_policy_group_modify(
                        new_active_replica_qos_policy, max_throughput)
                vserver_client.set_qos_policy_group_for_volume(
                    volume_name_on_backend, new_active_replica_qos_policy)

                LOG.info("QoS policy applied successfully for promoted "
                         "replica: %s", new_active_replica['id'])
            except Exception:
                LOG.exception("Could not apply QoS to the promoted replica.")

    def _convert_destination_replica_to_independent(
            self, context, dm_session, orig_active_replica, replica,
            access_rules, share_server=None):
        """Breaks SnapMirror and allows r/w ops on the destination replica.

        For promotion, the existing SnapMirror relationship must be broken
        and access rules have to be granted to the broken off replica to
        use it as an independent share.
        :param context: Request Context
        :param dm_session: Data motion object for SnapMirror operations
        :param orig_active_replica: Original SnapMirror source
        :param replica: Replica to promote to SnapMirror source
        :param access_rules: Access rules to apply to the replica
        :param share_server: ShareServer class instance of replica
        :return: Updated replica
        """
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_backend_share_name(replica['id'])

        try:
            # 1. Start an update to try to get a last minute transfer before we
            # quiesce and break
            dm_session.update_snapmirror(orig_active_replica, replica)
        except exception.StorageCommunicationException:
            # Ignore any errors since the current source replica may be
            # unreachable
            pass
        # 2. Break SnapMirror
        dm_session.break_snapmirror(orig_active_replica, replica)

        # 3. Setup access rules
        new_active_replica = copy.deepcopy(replica)
        helper = self._get_helper(replica)
        helper.set_client(vserver_client)
        try:
            helper.update_access(replica, share_name, access_rules)
        except Exception:
            new_active_replica['access_rules_status'] = (
                constants.SHARE_INSTANCE_RULES_SYNCING)
        else:
            new_active_replica['access_rules_status'] = constants.STATUS_ACTIVE

        new_active_replica['export_locations'] = self._create_export(
            new_active_replica, share_server, vserver, vserver_client)
        new_active_replica['replica_state'] = constants.REPLICA_STATE_ACTIVE
        return new_active_replica

    def _safe_change_replica_source(self, dm_session, replica,
                                    orig_source_replica,
                                    new_source_replica, replica_list):
        """Attempts to change the SnapMirror source to new source.

        If the attempt fails, 'replica_state' is set to 'error'.
        :param dm_session: Data motion object for SnapMirror operations
        :param replica: Replica that requires a change of source
        :param orig_source_replica: Original SnapMirror source volume
        :param new_source_replica: New SnapMirror source volume
        :return: Updated replica
        """
        try:
            dm_session.change_snapmirror_source(replica,
                                                orig_source_replica,
                                                new_source_replica,
                                                replica_list)
        except exception.StorageCommunicationException:
            replica['status'] = constants.STATUS_ERROR
            replica['replica_state'] = constants.STATUS_ERROR
            replica['export_locations'] = []
            msg = ("Failed to change replica (%s) to a SnapMirror "
                   "destination. Replica backend is unreachable.")

            LOG.exception(msg, replica['id'])
            return replica
        except netapp_api.NaApiError:
            replica['replica_state'] = constants.STATUS_ERROR
            replica['export_locations'] = []
            msg = ("Failed to change replica (%s) to a SnapMirror "
                   "destination.")
            LOG.exception(msg, replica['id'])
            return replica

        replica['replica_state'] = constants.REPLICA_STATE_OUT_OF_SYNC
        replica['export_locations'] = []

        return replica

    def create_replicated_snapshot(self, context, replica_list,
                                   snapshot_instances, share_server=None):
        active_replica = self._find_active_replica(replica_list)
        active_snapshot = [x for x in snapshot_instances
                           if x['share_id'] == active_replica['id']][0]
        snapshot_name = self._get_backend_snapshot_name(active_snapshot['id'])

        self.create_snapshot(context, active_snapshot,
                             share_server=share_server)

        active_snapshot['status'] = constants.STATUS_AVAILABLE
        active_snapshot['provider_location'] = snapshot_name
        snapshots = [active_snapshot]
        instances = zip(sorted(replica_list,
                               key=lambda x: x['id']),
                        sorted(snapshot_instances,
                               key=lambda x: x['share_id']))

        for replica, snapshot in instances:
            if snapshot['id'] != active_snapshot['id']:
                snapshot['provider_location'] = snapshot_name
                snapshots.append(snapshot)
                dm_session = data_motion.DataMotionSession()
                if replica.get('host'):
                    try:
                        dm_session.update_snapmirror(active_replica,
                                                     replica)
                    except netapp_api.NaApiError as e:
                        if e.code != netapp_api.EOBJECTNOTFOUND:
                            raise
        return snapshots

    def delete_replicated_snapshot(self, context, replica_list,
                                   snapshot_instances, share_server=None):
        active_replica = self._find_active_replica(replica_list)
        active_snapshot = [x for x in snapshot_instances
                           if x['share_id'] == active_replica['id']][0]

        self.delete_snapshot(context, active_snapshot,
                             share_server=share_server,
                             snapshot_name=active_snapshot['provider_location']
                             )
        active_snapshot['status'] = constants.STATUS_DELETED
        instances = zip(sorted(replica_list,
                               key=lambda x: x['id']),
                        sorted(snapshot_instances,
                               key=lambda x: x['share_id']))

        for replica, snapshot in instances:
            if snapshot['id'] != active_snapshot['id']:
                dm_session = data_motion.DataMotionSession()
                if replica.get('host'):
                    try:
                        dm_session.update_snapmirror(active_replica, replica)
                    except netapp_api.NaApiError as e:
                        if e.code != netapp_api.EOBJECTNOTFOUND:
                            raise

        return [active_snapshot]

    def update_replicated_snapshot(self, replica_list, share_replica,
                                   snapshot_instances, snapshot_instance,
                                   share_server=None):
        active_replica = self._find_active_replica(replica_list)
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_backend_share_name(
            snapshot_instance['share_id'])
        snapshot_name = snapshot_instance.get('provider_location')
        # NOTE(ameade): If there is no provider location,
        # then grab from active snapshot instance
        if snapshot_name is None:
            active_snapshot = [x for x in snapshot_instances
                               if x['share_id'] == active_replica['id']][0]
            snapshot_name = active_snapshot.get('provider_location')
            if not snapshot_name:
                return

        try:
            snapshot_exists = vserver_client.snapshot_exists(snapshot_name,
                                                             share_name)
        except exception.SnapshotUnavailable:
            # The volume must still be offline
            return

        if (snapshot_exists and
                snapshot_instance['status'] == constants.STATUS_CREATING):
            return {
                'status': constants.STATUS_AVAILABLE,
                'provider_location': snapshot_name,
            }
        elif (not snapshot_exists and
              snapshot_instance['status'] == constants.STATUS_DELETING):
            raise exception.SnapshotResourceNotFound(
                name=snapshot_instance.get('provider_location'))

        dm_session = data_motion.DataMotionSession()
        try:
            dm_session.update_snapmirror(active_replica, share_replica)
        except netapp_api.NaApiError as e:
            if e.code != netapp_api.EOBJECTNOTFOUND:
                raise

    def revert_to_replicated_snapshot(self, context, active_replica,
                                      replica_list, active_replica_snapshot,
                                      replica_snapshots, share_server=None):
        """Reverts a replicated share (in place) to the specified snapshot."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_name = self._get_backend_share_name(
            active_replica_snapshot['share_id'])
        snapshot_name = (
            active_replica_snapshot.get('provider_location') or
            self._get_backend_snapshot_name(active_replica_snapshot['id']))

        LOG.debug('Restoring snapshot %s', snapshot_name)

        dm_session = data_motion.DataMotionSession()
        non_active_replica_list = self._find_nonactive_replicas(replica_list)

        # Ensure source snapshot exists
        vserver_client.get_snapshot(share_name, snapshot_name)

        # Break all mirrors
        for replica in non_active_replica_list:
            try:
                dm_session.break_snapmirror(
                    active_replica, replica, mount=False)
            except netapp_api.NaApiError as e:
                if e.code != netapp_api.EOBJECTNOTFOUND:
                    raise

        # Delete source SnapMirror snapshots that will prevent a snap restore
        snapmirror_snapshot_names = vserver_client.list_snapmirror_snapshots(
            share_name)
        for snapmirror_snapshot_name in snapmirror_snapshot_names:
            vserver_client.delete_snapshot(
                share_name, snapmirror_snapshot_name, ignore_owners=True)

        # Restore source snapshot of interest
        vserver_client.restore_snapshot(share_name, snapshot_name)

        # Reestablish mirrors
        for replica in non_active_replica_list:
            try:
                dm_session.resync_snapmirror(active_replica, replica)
            except netapp_api.NaApiError as e:
                if e.code != netapp_api.EOBJECTNOTFOUND:
                    raise

    def _check_destination_vserver_for_vol_move(self, source_share,
                                                source_vserver,
                                                dest_share_server):
        try:
            destination_vserver, __ = self._get_vserver(
                share_server=dest_share_server)
        except exception.InvalidParameterValue:
            destination_vserver = None

        if source_vserver != destination_vserver:
            msg = _("Cannot migrate %(shr)s efficiently from source "
                    "VServer %(src)s to destination VServer %(dest)s.")
            msg_args = {
                'shr': source_share['id'],
                'src': source_vserver,
                'dest': destination_vserver,
            }
            raise exception.NetAppException(msg % msg_args)

    def migration_check_compatibility(self, context, source_share,
                                      destination_share, share_server=None,
                                      destination_share_server=None):
        """Checks compatibility between self.host and destination host."""
        # We need cluster creds to perform an intra-cluster data motion
        compatible = False
        destination_host = destination_share['host']

        if self._have_cluster_creds:
            try:
                backend = share_utils.extract_host(
                    destination_host, level='backend_name')
                destination_aggregate = share_utils.extract_host(
                    destination_host, level='pool')
                # Validate new extra-specs are valid on the destination
                extra_specs = share_types.get_extra_specs_from_share(
                    destination_share)
                self._check_extra_specs_validity(
                    destination_share, extra_specs)
                # TODO(gouthamr): Check whether QoS min-throughputs can be
                # honored on the destination aggregate when supported.
                self._check_aggregate_extra_specs_validity(
                    destination_aggregate, extra_specs)

                data_motion.get_backend_configuration(backend)

                source_vserver, __ = self._get_vserver(
                    share_server=share_server)
                share_volume = self._get_backend_share_name(
                    source_share['id'])

                self._check_destination_vserver_for_vol_move(
                    source_share, source_vserver, destination_share_server)

                encrypt_dest = self._get_dest_flexvol_encryption_value(
                    destination_share)
                self._client.check_volume_move(
                    share_volume, source_vserver, destination_aggregate,
                    encrypt_destination=encrypt_dest)

            except Exception:
                msg = ("Cannot migrate share %(shr)s efficiently between "
                       "%(src)s and %(dest)s.")
                msg_args = {
                    'shr': source_share['id'],
                    'src': source_share['host'],
                    'dest': destination_host,
                }
                LOG.exception(msg, msg_args)
            else:
                compatible = True
        else:
            msg = ("Cluster credentials have not been configured "
                   "with this share driver. Cannot perform volume move "
                   "operations.")
            LOG.warning(msg)

        compatibility = {
            'compatible': compatible,
            'writable': compatible,
            'nondisruptive': compatible,
            'preserve_metadata': compatible,
            'preserve_snapshots': compatible,
        }

        return compatibility

    def migration_start(self, context, source_share, destination_share,
                        source_snapshots, snapshot_mappings,
                        share_server=None, destination_share_server=None):
        """Begins data motion from source_share to destination_share."""
        # Intra-cluster migration
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_volume = self._get_backend_share_name(source_share['id'])
        destination_aggregate = share_utils.extract_host(
            destination_share['host'], level='pool')

        # If the destination's share type extra-spec for Flexvol encryption
        # is different than the source's, then specify the volume-move
        # operation to set the correct 'encrypt' attribute on the destination
        # volume.
        encrypt_dest = self._get_dest_flexvol_encryption_value(
            destination_share)

        self._client.start_volume_move(
            share_volume,
            vserver,
            destination_aggregate,
            encrypt_destination=encrypt_dest)

        msg = ("Began volume move operation of share %(shr)s from %(src)s "
               "to %(dest)s.")
        msg_args = {
            'shr': source_share['id'],
            'src': source_share['host'],
            'dest': destination_share['host'],
        }
        LOG.info(msg, msg_args)

    def _get_volume_move_status(self, source_share, share_server):
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_volume = self._get_backend_share_name(source_share['id'])
        status = self._client.get_volume_move_status(share_volume, vserver)
        return status

    def _get_dest_flexvol_encryption_value(self, destination_share):
        dest_share_type_encrypted_val = share_types.get_share_type_extra_specs(
            destination_share['share_type_id'],
            'netapp_flexvol_encryption')
        encrypt_destination = share_types.parse_boolean_extra_spec(
            'netapp_flexvol_encryption', dest_share_type_encrypted_val)

        return encrypt_destination

    def migration_continue(self, context, source_share, destination_share,
                           source_snapshots, snapshot_mappings,
                           share_server=None, destination_share_server=None):
        """Check progress of migration, try to repair data motion errors."""
        status = self._get_volume_move_status(source_share, share_server)
        completed_phases = (
            'cutover_hard_deferred', 'cutover_soft_deferred', 'completed')

        move_phase = status['phase'].lower()
        if move_phase == 'failed':
            msg_args = {
                'shr': source_share['id'],
                'reason': status['details'],
            }
            msg = _("Volume move operation for share %(shr)s failed. Reason: "
                    "%(reason)s") % msg_args
            LOG.exception(msg)
            raise exception.NetAppException(msg)
        elif move_phase in completed_phases:
            return True

        return False

    def migration_get_progress(self, context, source_share,
                               destination_share, source_snapshots,
                               snapshot_mappings, share_server=None,
                               destination_share_server=None):
        """Return detailed progress of the migration in progress."""
        status = self._get_volume_move_status(source_share, share_server)

        # NOTE (gouthamr): If the volume move is waiting for a manual
        # intervention to cut-over, the copy is done with respect to the
        # user. Volume move copies the rest of the data before cut-over anyway.
        if status['phase'] in ('cutover_hard_deferred',
                               'cutover_soft_deferred'):
            status['percent-complete'] = 100

        msg = ("Volume move status for share %(share)s: (State) %(state)s. "
               "(Phase) %(phase)s. Details: %(details)s")
        msg_args = {
            'state': status['state'],
            'details': status['details'],
            'share': source_share['id'],
            'phase': status['phase'],
        }
        LOG.info(msg, msg_args)

        return {
            'total_progress': status['percent-complete'] or 0,
            'state': status['state'],
            'estimated_completion_time': status['estimated-completion-time'],
            'phase': status['phase'],
            'details': status['details'],
        }

    def migration_cancel(self, context, source_share, destination_share,
                         source_snapshots, snapshot_mappings,
                         share_server=None, destination_share_server=None):
        """Abort an ongoing migration."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_volume = self._get_backend_share_name(source_share['id'])

        try:
            self._get_volume_move_status(source_share, share_server)
        except exception.NetAppException:
            LOG.exception("Could not get volume move status.")
            return

        self._client.abort_volume_move(share_volume, vserver)

        msg = ("Share volume move operation for share %(shr)s from host "
               "%(src)s to %(dest)s was successfully aborted.")
        msg_args = {
            'shr': source_share['id'],
            'src': source_share['host'],
            'dest': destination_share['host'],
        }
        LOG.info(msg, msg_args)

    def migration_complete(self, context, source_share, destination_share,
                           source_snapshots, snapshot_mappings,
                           share_server=None, destination_share_server=None):
        """Initiate the cutover to destination share after move is complete."""
        vserver, vserver_client = self._get_vserver(share_server=share_server)
        share_volume = self._get_backend_share_name(source_share['id'])

        status = self._get_volume_move_status(source_share, share_server)

        move_phase = status['phase'].lower()
        if move_phase == 'completed':
            LOG.debug("Volume move operation was already successfully "
                      "completed for share %(shr)s.",
                      {'shr': source_share['id']})
        elif move_phase in ('cutover_hard_deferred', 'cutover_soft_deferred'):
            self._client.trigger_volume_move_cutover(share_volume, vserver)
            self._wait_for_cutover_completion(
                source_share, share_server)
        else:
            msg_args = {
                'shr': source_share['id'],
                'status': status['state'],
                'phase': status['phase'],
                'details': status['details'],
            }
            msg = _("Cannot complete volume move operation for share %(shr)s. "
                    "Current volume move status: %(status)s, phase: "
                    "%(phase)s. Details: %(details)s") % msg_args
            LOG.exception(msg)
            raise exception.NetAppException(msg)

        new_share_volume_name = self._get_backend_share_name(
            destination_share['id'])
        vserver_client.set_volume_name(share_volume, new_share_volume_name)

        # Modify volume properties per share type extra-specs
        extra_specs = share_types.get_extra_specs_from_share(
            destination_share)
        provisioning_options = self._get_provisioning_options(extra_specs)
        qos_policy_group_name = self._modify_or_create_qos_for_existing_share(
            destination_share, extra_specs, vserver, vserver_client)
        if qos_policy_group_name:
            provisioning_options['qos_policy_group'] = qos_policy_group_name
        destination_aggregate = share_utils.extract_host(
            destination_share['host'], level='pool')

        # Modify volume to match extra specs
        vserver_client.modify_volume(destination_aggregate,
                                     new_share_volume_name,
                                     **provisioning_options)

        msg = ("Volume move operation for share %(shr)s has completed "
               "successfully. Share has been moved from %(src)s to "
               "%(dest)s.")
        msg_args = {
            'shr': source_share['id'],
            'src': source_share['host'],
            'dest': destination_share['host'],
        }
        LOG.info(msg, msg_args)

        # NOTE(gouthamr): For nondisruptive migration, current export
        # policy will not be cleared, the export policy will be renamed to
        # match the name of the share.
        export_locations = self._create_export(
            destination_share, share_server, vserver, vserver_client,
            clear_current_export_policy=False)
        src_snaps_dict = {s['id']: s for s in source_snapshots}
        snapshot_updates = {}

        for source_snap_id, destination_snap in snapshot_mappings.items():
            p_location = src_snaps_dict[source_snap_id]['provider_location']

            snapshot_updates.update(
                {destination_snap['id']: {'provider_location': p_location}})

        return {
            'export_locations': export_locations,
            'snapshot_updates': snapshot_updates,
        }

    @na_utils.trace
    def _modify_or_create_qos_for_existing_share(self, share, extra_specs,
                                                 vserver, vserver_client):
        """Gets/Creates QoS policy for an existing FlexVol.

        The share's assigned QoS policy is renamed and adjusted if the policy
        is exclusive to the FlexVol. If the policy includes other workloads
        besides the FlexVol, a new policy is created with the specs necessary.
        """
        qos_specs = self._get_normalized_qos_specs(extra_specs)
        if not qos_specs:
            return

        backend_share_name = self._get_backend_share_name(share['id'])
        qos_policy_group_name = self._get_backend_qos_policy_group_name(
            share['id'])

        create_new_qos_policy_group = True

        backend_volume = vserver_client.get_volume(
            backend_share_name)
        backend_volume_size = int(
            math.ceil(float(backend_volume['size']) / units.Gi))

        LOG.debug("Checking for a pre-existing QoS policy group that "
                  "is exclusive to the volume %s.", backend_share_name)

        # Does the volume have an exclusive QoS policy that we can rename?
        if backend_volume['qos-policy-group-name'] is not None:
            existing_qos_policy_group = self._client.qos_policy_group_get(
                backend_volume['qos-policy-group-name'])
            if existing_qos_policy_group['num-workloads'] == 1:
                # Yay, can set max-throughput and rename

                msg = ("Found pre-existing QoS policy %(policy)s and it is "
                       "exclusive to the volume %(volume)s. Modifying and "
                       "renaming this policy to %(new_policy)s.")
                msg_args = {
                    'policy': backend_volume['qos-policy-group-name'],
                    'volume': backend_share_name,
                    'new_policy': qos_policy_group_name,
                }
                LOG.debug(msg, msg_args)

                max_throughput = self._get_max_throughput(
                    backend_volume_size, qos_specs)
                self._client.qos_policy_group_modify(
                    backend_volume['qos-policy-group-name'], max_throughput)
                self._client.qos_policy_group_rename(
                    backend_volume['qos-policy-group-name'],
                    qos_policy_group_name)
                create_new_qos_policy_group = False

        if create_new_qos_policy_group:
            share_obj = {
                'size': backend_volume_size,
                'id': share['id'],
            }
            LOG.debug("No existing QoS policy group found for "
                      "volume. Creating  a new one with name %s.",
                      qos_policy_group_name)
            self._create_qos_policy_group(share_obj, vserver, qos_specs)
        return qos_policy_group_name

    def _wait_for_cutover_completion(self, source_share, share_server):

        retries = (self.configuration.netapp_volume_move_cutover_timeout / 5
                   or 1)

        @manila_utils.retry(exception.ShareBusyException, interval=5,
                            retries=retries, backoff_rate=1)
        def check_move_completion():
            status = self._get_volume_move_status(source_share, share_server)
            if status['phase'].lower() != 'completed':
                msg_args = {
                    'shr': source_share['id'],
                    'phs': status['phase'],
                }
                msg = _('Volume move operation for share %(shr)s is not '
                        'complete. Current Phase: %(phs)s. '
                        'Retrying.') % msg_args
                LOG.warning(msg)
                raise exception.ShareBusyException(reason=msg)

        try:
            check_move_completion()
        except exception.ShareBusyException:
            msg = _("Volume move operation did not complete after cut-over "
                    "was triggered. Retries exhausted. Not retrying.")
            raise exception.NetAppException(message=msg)
