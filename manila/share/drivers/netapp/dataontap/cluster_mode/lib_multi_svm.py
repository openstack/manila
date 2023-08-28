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
NetApp Data ONTAP cDOT multi-SVM storage driver library.

This library extends the abstract base library and completes the multi-SVM
functionality needed by the cDOT multi-SVM Manila driver.  This library
variant creates Data ONTAP storage virtual machines (i.e. 'vservers')
as needed to provision shares.
"""
import re

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import excutils
from oslo_utils import units

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.message import message_field
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.cluster_mode import data_motion
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_base
from manila.share.drivers.netapp import utils as na_utils
from manila.share import share_types
from manila.share import utils as share_utils
from manila import utils

LOG = log.getLogger(__name__)
SUPPORTED_NETWORK_TYPES = (None, 'flat', 'vlan')
SEGMENTED_NETWORK_TYPES = ('vlan',)
DEFAULT_MTU = 1500
CLUSTER_IPSPACES = ('Cluster', 'Default')
SERVER_MIGRATE_SVM_DR = 'svm_dr'
SERVER_MIGRATE_SVM_MIGRATE = 'svm_migrate'
METADATA_VLAN = 'set_vlan'
METADATA_MTU = 'set_mtu'


class NetAppCmodeMultiSVMFileStorageLibrary(
        lib_base.NetAppCmodeFileStorageLibrary):

    @na_utils.trace
    def check_for_setup_error(self):

        if self._have_cluster_creds:
            if self.configuration.netapp_vserver:
                msg = ('Vserver is specified in the configuration. This is '
                       'ignored when the driver is managing share servers.')
                LOG.warning(msg)

        else:  # only have vserver creds, which is an error in multi_svm mode
            msg = _('Cluster credentials must be specified in the '
                    'configuration when the driver is managing share servers.')
            raise exception.InvalidInput(reason=msg)

        # Ensure FlexGroup support
        aggr_list = self._client.list_non_root_aggregates()
        self._initialize_flexgroup_pools(set(aggr_list))

        # Ensure one or more aggregates are available.
        if (self.is_flexvol_pool_configured() and
                not self._find_matching_aggregates(aggregate_names=aggr_list)):
            msg = _('No aggregates are available for provisioning shares. '
                    'Ensure that the configuration option '
                    'netapp_aggregate_name_search_pattern is set correctly.')
            raise exception.NetAppException(msg)

        (super(NetAppCmodeMultiSVMFileStorageLibrary, self).
            check_for_setup_error())

    @na_utils.trace
    def _get_vserver(self, share_server=None, vserver_name=None,
                     backend_name=None):
        if share_server:
            backend_details = share_server.get('backend_details')
            vserver = backend_details.get(
                'vserver_name') if backend_details else None

            if not vserver:
                msg = _('Vserver name is absent in backend details. Please '
                        'check whether Vserver was created properly.')
                raise exception.VserverNotSpecified(msg)
        elif vserver_name:
            vserver = vserver_name
        else:
            msg = _('Share server or vserver name not provided')
            raise exception.InvalidInput(reason=msg)

        if backend_name:
            vserver_client = data_motion.get_client_for_backend(
                backend_name, vserver
            )
        else:
            vserver_client = self._get_api_client(vserver)

        if not vserver_client.vserver_exists(vserver):
            raise exception.VserverNotFound(vserver=vserver)

        return vserver, vserver_client

    def _get_ems_pool_info(self):
        return {
            'pools': {
                'vserver': None,
                'aggregates': self._find_matching_aggregates(),
                'flexgroup_aggregates': self._flexgroup_pools,
            },
        }

    @na_utils.trace
    def _handle_housekeeping_tasks(self):
        """Handle various cleanup activities."""
        self._client.prune_deleted_nfs_export_policies()
        self._client.prune_deleted_snapshots()
        self._client.remove_unused_qos_policy_groups()

        (super(NetAppCmodeMultiSVMFileStorageLibrary, self).
            _handle_housekeeping_tasks())

    @na_utils.trace
    def _find_matching_aggregates(self, aggregate_names=None):
        """Find all aggregates match pattern."""

        if not self.is_flexvol_pool_configured():
            return []

        if not aggregate_names:
            aggregate_names = self._client.list_non_root_aggregates()

        pattern = self.configuration.netapp_aggregate_name_search_pattern
        return [aggr_name for aggr_name in aggregate_names
                if re.match(pattern, aggr_name)]

    @na_utils.trace
    def _set_network_with_metadata(self, network_info):
        """Set the subnet metadata information for network_info object."""

        for network in network_info:
            metadata = network.get('subnet_metadata')
            if not metadata:
                continue

            metadata_vlan = metadata.get(METADATA_VLAN)
            if not metadata_vlan:
                continue

            if int(metadata_vlan) > 4094 or int(metadata_vlan) < 1:
                msg = _(
                    'A segmentation ID %s was specified but is not valid for '
                    'a VLAN network type; the segmentation ID must be an '
                    'integer value in the range of [1,4094]')
                raise exception.NetworkBadConfigurationException(
                    reason=msg % metadata_vlan)

            if metadata.get(METADATA_MTU) is not None:
                try:
                    int(metadata.get(METADATA_MTU))
                except ValueError:
                    msg = _('Metadata network MTU must be an integer value.')
                    raise exception.NetworkBadConfigurationException(msg)

            network['network_type'] = 'vlan'
            network['segmentation_id'] = metadata_vlan
            for allocation in network['network_allocations']:
                allocation['network_type'] = 'vlan'
                allocation['segmentation_id'] = metadata_vlan
                allocation['mtu'] = int(metadata.get(METADATA_MTU) or
                                        allocation['mtu'])

    @na_utils.trace
    def setup_server(self, network_info, metadata=None):
        """Creates and configures new Vserver."""

        # only changes network_info if one of networks has metadata set.
        self._set_network_with_metadata(network_info)

        ports = {}
        server_id = network_info[0]['server_id']
        LOG.debug("Setting up server %s.", server_id)
        for network in network_info:
            for network_allocation in network['network_allocations']:
                ports[network_allocation['id']] = (
                    network_allocation['ip_address'])

        nfs_config = self._default_nfs_config
        if (self.is_nfs_config_supported and metadata and
                'share_type_id' in metadata):
            extra_specs = share_types.get_share_type_extra_specs(
                metadata['share_type_id'])
            self._check_nfs_config_extra_specs_validity(extra_specs)
            nfs_config = self._get_nfs_config_provisioning_options(extra_specs)

        vlan = network_info[0]['segmentation_id']

        @utils.synchronized('netapp-VLAN-%s' % vlan, external=True)
        def setup_server_with_lock():
            self._validate_network_type(network_info)

            # Before proceeding, make sure subnet configuration is valid
            self._validate_share_network_subnets(network_info)

            vserver_name = self._get_vserver_name(server_id)
            server_details = {
                'vserver_name': vserver_name,
                'ports': jsonutils.dumps(ports),
            }

            if self.is_nfs_config_supported:
                server_details['nfs_config'] = jsonutils.dumps(nfs_config)

            try:
                self._create_vserver(vserver_name, network_info, metadata,
                                     nfs_config=nfs_config)
            except Exception as e:
                e.detail_data = {'server_details': server_details}
                raise

            return server_details

        return setup_server_with_lock()

    @na_utils.trace
    def _check_nfs_config_extra_specs_validity(self, extra_specs):
        """Check if the nfs config extra_spec has valid values."""
        int_extra_specs = ['netapp:tcp_max_xfer_size',
                           'netapp:udp_max_xfer_size']
        for key in int_extra_specs:
            if key in extra_specs:
                self._check_if_extra_spec_is_positive(
                    extra_specs[key], key)

    @na_utils.trace
    def _check_if_extra_spec_is_positive(self, value, key):
        """Check if extra_spec has a valid positive int value."""
        if int(value) < 0:
            args = {'value': value, 'key': key}
            msg = _('Invalid value "%(value)s" for extra_spec "%(key)s" '
                    'used by share server setup.')
            raise exception.NetAppException(msg % args)

    @na_utils.trace
    def _get_nfs_config_provisioning_options(self, specs):
        """Return the nfs config provisioning option."""
        nfs_config = self.get_string_provisioning_options(
            specs, self.NFS_CONFIG_EXTRA_SPECS_MAP)

        # Changes the no set config to the default value
        for k, v in nfs_config.items():
            if v is None:
                nfs_config[k] = self._default_nfs_config[k]

        return nfs_config

    @na_utils.trace
    def _validate_network_type(self, network_info):
        """Raises exception if the segmentation type is incorrect."""
        unsupported_nets = [network for network in network_info
                            if network['network_type']
                            not in SUPPORTED_NETWORK_TYPES]

        if unsupported_nets:
            msg = _('The specified network type %s is unsupported by the '
                    'NetApp clustered Data ONTAP driver')
            raise exception.NetworkBadConfigurationException(
                reason=msg % unsupported_nets[0]['network_type'])

    @na_utils.trace
    def _get_vserver_name(self, server_id):
        return self.configuration.netapp_vserver_name_template % server_id

    @na_utils.trace
    def _validate_share_network_subnets(self, network_info):
        """Raises exception if subnet configuration isn't valid."""
        # Driver supports multiple subnets only if in the same network segment
        ref_vlan = network_info[0]['segmentation_id']
        if not all([network['segmentation_id'] == ref_vlan
                    for network in network_info]):
            msg = _("The specified network configuration isn't supported by "
                    "the NetApp clustered Data ONTAP driver. All subnets must "
                    "reside in the same network segment.")
            raise exception.NetworkBadConfigurationException(reason=msg)

    @na_utils.trace
    def _create_vserver(self, vserver_name, network_info, metadata=None,
                        nfs_config=None):
        """Creates Vserver with given parameters if it doesn't exist."""

        if self._client.vserver_exists(vserver_name):
            msg = _('Vserver %s already exists.')
            raise exception.NetAppException(msg % vserver_name)
        # NOTE(dviroel): check if this vserver will be a data protection server
        is_dp_destination = False
        if metadata and metadata.get('migration_destination') is True:
            is_dp_destination = True
            msg = _("Starting creation of a vserver with 'dp_destination' "
                    "subtype.")
            LOG.debug(msg)

        # NOTE(lseki): If there's already an ipspace created for the same VLAN
        # port, reuse it. It will be named after the previously created share
        # server's neutron subnet id.
        node_name = self._client.list_cluster_nodes()[0]
        port = self._get_node_data_port(node_name)
        # NOTE(sfernand): ONTAP driver currently supports multiple subnets
        # only in a same network segment. A validation is performed in a
        # earlier step to make sure all subnets have the same segmentation_id.
        vlan = network_info[0]['segmentation_id']
        ipspace_name = self._client.get_ipspace_name_for_vlan_port(
            node_name, port, vlan) or self._create_ipspace(network_info[0])

        aggregate_names = self._find_matching_aggregates()
        if is_dp_destination:
            # Get Data ONTAP aggregate name as pool name.
            LOG.debug('Creating a new Vserver (%s) for data protection.',
                      vserver_name)
            self._client.create_vserver_dp_destination(
                vserver_name,
                aggregate_names,
                ipspace_name)
            # Set up port and broadcast domain for the current ipspace
            self._create_port_and_broadcast_domain(
                ipspace_name, network_info[0])
        else:
            LOG.debug('Vserver %s does not exist, creating.', vserver_name)
            aggr_set = set(aggregate_names).union(
                self._get_flexgroup_aggr_set())
            self._client.create_vserver(
                vserver_name,
                self.configuration.netapp_root_volume_aggregate,
                self.configuration.netapp_root_volume,
                aggr_set,
                ipspace_name,
                self.configuration.netapp_security_cert_expire_days)

            vserver_client = self._get_api_client(vserver=vserver_name)

            security_services = network_info[0].get('security_services')
            try:
                self._setup_network_for_vserver(
                    vserver_name, vserver_client, network_info, ipspace_name,
                    security_services=security_services, nfs_config=nfs_config)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error("Failed to configure Vserver.")
                    # NOTE(dviroel): At this point, the lock was already
                    # acquired by the caller of _create_vserver.
                    self._delete_vserver(vserver_name,
                                         security_services=security_services,
                                         needs_lock=False)

    def _setup_network_for_vserver(self, vserver_name, vserver_client,
                                   network_info, ipspace_name,
                                   enable_nfs=True, security_services=None,
                                   nfs_config=None):
        """Setup Vserver network configuration"""
        # segmentation_id and mtu are the same for all allocations and can be
        # extracted from the first index, as subnets were previously checked
        # at this point to ensure they are all in the same network segment and
        # consequently belongs to the same Neutron network (which holds L2
        # information).
        ref_subnet_allocation = network_info[0]['network_allocations'][0]
        vlan = ref_subnet_allocation['segmentation_id']
        mtu = ref_subnet_allocation['mtu'] or DEFAULT_MTU

        home_ports = {}
        nodes = self._client.list_cluster_nodes()
        for node in nodes:
            port = self._get_node_data_port(node)
            vlan_port_name = self._client.create_port_and_broadcast_domain(
                node, port, vlan, mtu, ipspace_name)
            home_ports[node] = vlan_port_name

        for network in network_info:
            self._create_vserver_lifs(vserver_name,
                                      vserver_client,
                                      network,
                                      ipspace_name,
                                      lif_home_ports=home_ports)

            self._create_vserver_routes(vserver_client, network)

        self._create_vserver_admin_lif(vserver_name,
                                       vserver_client,
                                       network_info[0],
                                       ipspace_name,
                                       lif_home_ports=home_ports)
        if enable_nfs:
            vserver_client.enable_nfs(
                self.configuration.netapp_enabled_share_protocols,
                nfs_config=nfs_config)

        if security_services:
            self._client.setup_security_services(security_services,
                                                 vserver_client,
                                                 vserver_name)

    def _get_valid_ipspace_name(self, network_id):
        """Get IPspace name according to network id."""
        return 'ipspace_' + network_id.replace('-', '_')

    @na_utils.trace
    def _create_ipspace(self, network_info, client=None):
        """If supported, create an IPspace for a new Vserver."""

        desired_client = client if client else self._client

        if not desired_client.features.IPSPACES:
            return None

        if (network_info['network_allocations'][0]['network_type']
                not in SEGMENTED_NETWORK_TYPES):
            return client_cmode.DEFAULT_IPSPACE

        # NOTE(cknight): Neutron needs cDOT IP spaces because it can provide
        # overlapping IP address ranges for different subnets.  That is not
        # believed to be an issue for any of Manila's other network plugins.
        ipspace_id = network_info.get('neutron_subnet_id')
        if not ipspace_id:
            return client_cmode.DEFAULT_IPSPACE

        ipspace_name = self._get_valid_ipspace_name(ipspace_id)
        desired_client.create_ipspace(ipspace_name)

        return ipspace_name

    @na_utils.trace
    def _create_vserver_lifs(self, vserver_name, vserver_client, network_info,
                             ipspace_name, lif_home_ports=None):
        """Create Vserver data logical interfaces (LIFs)."""
        # We can get node names directly from lif_home_ports in case
        # it was passed as parameter, otherwise a request to the cluster is
        nodes = (list(lif_home_ports.keys()) if lif_home_ports
                 else self._client.list_cluster_nodes())
        # required

        node_network_info = zip(nodes, network_info['network_allocations'])
        # Creating LIF per node
        for node_name, network_allocation in node_network_info:
            lif_home_port = (lif_home_ports[node_name] if
                             lif_home_ports else None)
            lif_name = self._get_lif_name(node_name, network_allocation)

            self._create_lif(vserver_client, vserver_name, ipspace_name,
                             node_name, lif_name, network_allocation,
                             lif_home_port=lif_home_port)

    @na_utils.trace
    def _create_vserver_admin_lif(self, vserver_name, vserver_client,
                                  network_info, ipspace_name,
                                  lif_home_ports=None):
        """Create Vserver admin LIF, if defined."""
        network_allocations = network_info.get('admin_network_allocations')
        if not network_allocations:
            return
        LOG.info('Admin network defined for Vserver %s.', vserver_name)

        home_port = None
        if lif_home_ports:
            node_name, home_port = list(lif_home_ports.items())[0]
        else:
            nodes = self._client.list_cluster_nodes()
            node_name = nodes[0]

        network_allocation = network_allocations[0]
        lif_name = self._get_lif_name(node_name, network_allocation)

        self._create_lif(vserver_client, vserver_name, ipspace_name,
                         node_name, lif_name, network_allocation,
                         lif_home_port=home_port)

    @na_utils.trace
    def _create_vserver_routes(self, vserver_client, network_info):
        """Create Vserver route and set gateways."""
        route_gateways = []
        # NOTE(gouthamr): Use the gateway from the tenant subnet/s
        # for the static routes. Do not configure a route for the admin
        # subnet because fast path routing will work for incoming
        # connections and there are no requirements for outgoing
        # connections on the admin network yet.
        for net_allocation in (network_info['network_allocations']):
            if net_allocation['gateway'] not in route_gateways:
                vserver_client.create_route(net_allocation['gateway'])
                route_gateways.append(net_allocation['gateway'])

    @na_utils.trace
    def _get_node_data_port(self, node):
        port_names = self._client.list_node_data_ports(node)
        pattern = self.configuration.netapp_port_name_search_pattern
        matched_port_names = [port_name for port_name in port_names
                              if re.match(pattern, port_name)]
        if not matched_port_names:
            raise exception.NetAppException(
                _('Could not find eligible network ports on node %s on which '
                  'to create Vserver LIFs.') % node)
        return matched_port_names[0]

    def _get_lif_name(self, node_name, network_allocation):
        """Get LIF name based on template from manila.conf file."""
        lif_name_args = {
            'node': node_name,
            'net_allocation_id': network_allocation['id'],
        }
        return self.configuration.netapp_lif_name_template % lif_name_args

    @na_utils.trace
    def _create_lif(self, vserver_client, vserver_name, ipspace_name,
                    node_name, lif_name, network_allocation,
                    lif_home_port=None):
        """Creates LIF for Vserver."""
        port = lif_home_port or self._get_node_data_port(node_name)
        vlan = network_allocation['segmentation_id']
        ip_address = network_allocation['ip_address']
        netmask = utils.cidr_to_netmask(network_allocation['cidr'])

        # We can skip the operation if an lif already exists with the same
        # configuration
        if vserver_client.network_interface_exists(
                vserver_name, node_name, port, ip_address, netmask, vlan,
                home_port=lif_home_port):
            msg = ('LIF %(ip)s netmask %(mask)s already exists for '
                   'node %(node)s port %(port)s in vserver %(vserver)s.' % {
                       'ip': ip_address,
                       'mask': netmask,
                       'node': node_name,
                       'vserver': vserver_name,
                       'port': '%(port)s-%(vlan)s' % {'port': port,
                                                      'vlan': vlan}})
            LOG.debug(msg)
            return

        if not lif_home_port:
            mtu = network_allocation.get('mtu') or DEFAULT_MTU
            lif_home_port = (
                self._client.create_port_and_broadcast_domain(
                    node_name, port, vlan, mtu, ipspace_name))

        self._client.create_network_interface(
            ip_address, netmask, node_name, lif_home_port,
            vserver_name, lif_name)

    @na_utils.trace
    def _create_port_and_broadcast_domain(self, ipspace_name, network_info):
        nodes = self._client.list_cluster_nodes()
        node_network_info = zip(nodes, network_info['network_allocations'])

        for node_name, network_allocation in node_network_info:

            port = self._get_node_data_port(node_name)
            vlan = network_allocation['segmentation_id']
            network_mtu = network_allocation.get('mtu')
            mtu = network_mtu or DEFAULT_MTU

            self._client.create_port_and_broadcast_domain(
                node_name, port, vlan, mtu, ipspace_name)

    @na_utils.trace
    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        return len(self._client.list_cluster_nodes())

    @na_utils.trace
    def get_admin_network_allocations_number(self, admin_network_api):
        """Get number of network allocations for creating admin LIFs."""
        return 1 if admin_network_api else 0

    @na_utils.trace
    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        vserver = server_details.get(
            'vserver_name') if server_details else None

        if not vserver:
            LOG.warning("Vserver not specified for share server being "
                        "deleted. Deletion of share server record will "
                        "proceed anyway.")
            return

        elif not self._client.vserver_exists(vserver):
            LOG.warning("Could not find Vserver for share server being "
                        "deleted: %s. Deletion of share server "
                        "record will proceed anyway.", vserver)
            return

        self._delete_vserver(vserver, security_services=security_services)

    @na_utils.trace
    def _delete_vserver(self, vserver, security_services=None,
                        needs_lock=True):
        """Delete a Vserver plus IPspace and security services as needed."""

        ipspace_name = self._client.get_vserver_ipspace(vserver)

        vserver_client = self._get_api_client(vserver=vserver)
        network_interfaces = vserver_client.get_network_interfaces()
        snapmirror_policies = self._client.get_snapmirror_policies(vserver)

        interfaces_on_vlans = []
        vlans = []
        for interface in network_interfaces:
            if '-' in interface['home-port']:
                interfaces_on_vlans.append(interface)
                vlans.append(interface['home-port'])

        if vlans:
            vlans = '-'.join(sorted(set(vlans))) if vlans else None
            vlan_id = vlans.split('-')[-1]
        else:
            vlan_id = None

        def _delete_vserver_without_lock():
            # NOTE(dviroel): always delete all policies before deleting the
            # vserver
            for policy in snapmirror_policies:
                vserver_client.delete_snapmirror_policy(policy)

            # NOTE(dviroel): Attempt to delete all vserver peering
            # created by replication
            self._delete_vserver_peers(vserver)

            self._client.delete_vserver(vserver,
                                        vserver_client,
                                        security_services=security_services)
            ipspace_deleted = False
            if (ipspace_name and ipspace_name not in CLUSTER_IPSPACES
                    and not self._client.ipspace_has_data_vservers(
                        ipspace_name)):
                self._client.delete_ipspace(ipspace_name)
                ipspace_deleted = True

            if not ipspace_name or ipspace_deleted:
                # NOTE(dviroel): only delete vlans if they are not being used
                # by any ipspaces and data vservers.
                self._delete_vserver_vlans(interfaces_on_vlans)

        @utils.synchronized('netapp-VLAN-%s' % vlan_id, external=True)
        def _delete_vserver_with_lock():
            _delete_vserver_without_lock()

        if needs_lock:
            return _delete_vserver_with_lock()
        else:
            return _delete_vserver_without_lock()

    @na_utils.trace
    def _delete_vserver_vlans(self, network_interfaces_on_vlans):
        """Delete Vserver's VLAN configuration from ports"""
        for interface in network_interfaces_on_vlans:
            try:
                home_port = interface['home-port']
                port, vlan = home_port.split('-')
                node = interface['home-node']
                self._client.delete_vlan(node, port, vlan)
            except exception.NetAppException:
                LOG.exception("Deleting Vserver VLAN failed.")

    @na_utils.trace
    def _delete_vserver_peers(self, vserver):
        vserver_peers = self._get_vserver_peers(vserver=vserver)
        for peer in vserver_peers:
            self._delete_vserver_peer(peer.get('vserver'),
                                      peer.get('peer-vserver'))

    def get_configured_ip_versions(self):
        versions = [4]
        options = self._client.get_net_options()
        if options['ipv6-enabled']:
            versions.append(6)
        return versions

    @na_utils.trace
    def create_replica(self, context, replica_list, new_replica,
                       access_rules, share_snapshots, share_server=None):
        """Creates the new replica on this backend and sets up SnapMirror.

        It creates the peering between the associated vservers before creating
        the share replica and setting up the SnapMirror.
        """
        # 1. Retrieve source and destination vservers from both replicas,
        # active and and new_replica
        src_vserver, dst_vserver = self._get_vservers_from_replicas(
            context, replica_list, new_replica)

        # 2. Retrieve the active replica host's client and cluster name
        src_replica = self.find_active_replica(replica_list)

        src_replica_host = share_utils.extract_host(
            src_replica['host'], level='backend_name')
        src_replica_client = data_motion.get_client_for_backend(
            src_replica_host, vserver_name=src_vserver)
        # Cluster name is needed for setting up the vserver peering
        src_replica_cluster_name = src_replica_client.get_cluster_name()

        # 3. Retrieve new replica host's client
        new_replica_host = share_utils.extract_host(
            new_replica['host'], level='backend_name')
        new_replica_client = data_motion.get_client_for_backend(
            new_replica_host, vserver_name=dst_vserver)
        new_replica_cluster_name = new_replica_client.get_cluster_name()

        if (dst_vserver != src_vserver
                and not self._get_vserver_peers(dst_vserver, src_vserver)):
            # 3.1. Request vserver peer creation from new_replica's host
            # to active replica's host
            new_replica_client.create_vserver_peer(
                dst_vserver, src_vserver,
                peer_cluster_name=src_replica_cluster_name)

            # 3.2. Accepts the vserver peering using active replica host's
            # client (inter-cluster only)
            if new_replica_cluster_name != src_replica_cluster_name:
                src_replica_client.accept_vserver_peer(src_vserver,
                                                       dst_vserver)

        return (super(NetAppCmodeMultiSVMFileStorageLibrary, self).
                create_replica(context, replica_list, new_replica,
                               access_rules, share_snapshots))

    def delete_replica(self, context, replica_list, replica, share_snapshots,
                       share_server=None):
        """Removes the replica on this backend and destroys SnapMirror.

        Removes the replica, destroys the SnapMirror and delete the vserver
        peering if needed.
        """
        vserver, peer_vserver = self._get_vservers_from_replicas(
            context, replica_list, replica)
        super(NetAppCmodeMultiSVMFileStorageLibrary, self).delete_replica(
            context, replica_list, replica, share_snapshots)

        # Check if there are no remaining SnapMirror connections and if a
        # vserver peering exists and delete it.
        snapmirrors = self._get_snapmirrors(vserver, peer_vserver)
        snapmirrors_from_peer = self._get_snapmirrors(peer_vserver, vserver)
        peers = self._get_vserver_peers(peer_vserver, vserver)
        if not (snapmirrors or snapmirrors_from_peer) and peers:
            self._delete_vserver_peer(peer_vserver, vserver)

    def manage_server(self, context, share_server, identifier, driver_options):
        """Manages a vserver by renaming it and returning backend_details."""
        new_vserver_name = self._get_vserver_name(share_server['id'])
        old_vserver_name = self._get_correct_vserver_old_name(identifier)
        if new_vserver_name != old_vserver_name:
            self._client.rename_vserver(old_vserver_name, new_vserver_name)

        backend_details = {
            'vserver_name': new_vserver_name,
        }

        if self.is_nfs_config_supported:
            nfs_config = self._client.get_nfs_config(
                list(self.NFS_CONFIG_EXTRA_SPECS_MAP.values()),
                new_vserver_name)
            backend_details['nfs_config'] = jsonutils.dumps(nfs_config)

        return new_vserver_name, backend_details

    def unmanage_server(self, server_details, security_services=None):
        pass

    def get_share_server_network_info(
            self, context, share_server, identifier, driver_options):
        """Returns a list of IPs for each vserver network interface."""
        vserver_name = self._get_correct_vserver_old_name(identifier)

        vserver, vserver_client = self._get_vserver(vserver_name=vserver_name)

        interfaces = vserver_client.get_network_interfaces()
        allocations = []
        for lif in interfaces:
            allocations.append(lif['address'])
        return allocations

    def _get_correct_vserver_old_name(self, identifier):

        # In case vserver_name includes the template, we check and add it here
        if not self._client.vserver_exists(identifier):
            return self._get_vserver_name(identifier)
        return identifier

    def _get_snapmirrors(self, vserver, peer_vserver):
        return self._client.get_snapmirrors(
            source_vserver=vserver, dest_vserver=peer_vserver)

    def _get_vservers_from_replicas(self, context, replica_list, new_replica):
        active_replica = self.find_active_replica(replica_list)

        dm_session = data_motion.DataMotionSession()
        vserver = dm_session.get_vserver_from_share(active_replica)
        peer_vserver = dm_session.get_vserver_from_share(new_replica)

        return vserver, peer_vserver

    def _get_vserver_peers(self, vserver=None, peer_vserver=None):
        return self._client.get_vserver_peers(vserver, peer_vserver)

    def _create_vserver_peer(self, context, vserver, peer_vserver):
        self._client.create_vserver_peer(vserver, peer_vserver)

    def _delete_vserver_peer(self, vserver, peer_vserver):
        self._client.delete_vserver_peer(vserver, peer_vserver)

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        # NOTE(dviroel): If both parent and child shares are in the same host,
        # they belong to the same cluster, and we can skip all the processing
        # below. Group snapshot is always to the same host too, so we can skip.
        is_group_snapshot = share.get('source_share_group_snapshot_member_id')
        if not is_group_snapshot and parent_share['host'] != share['host']:
            # 1. Retrieve source and destination vservers from source and
            # destination shares
            dm_session = data_motion.DataMotionSession()
            src_vserver = dm_session.get_vserver_from_share(parent_share)
            dest_vserver = dm_session.get_vserver_from_share_server(
                share_server)

            # 2. Retrieve the source share host's client and cluster name
            src_share_host = share_utils.extract_host(
                parent_share['host'], level='backend_name')
            src_share_client = data_motion.get_client_for_backend(
                src_share_host, vserver_name=src_vserver)
            # Cluster name is needed for setting up the vserver peering
            src_share_cluster_name = src_share_client.get_cluster_name()

            # 3. Retrieve new share host's client
            dest_share_host = share_utils.extract_host(
                share['host'], level='backend_name')
            dest_share_client = data_motion.get_client_for_backend(
                dest_share_host, vserver_name=dest_vserver)
            dest_share_cluster_name = dest_share_client.get_cluster_name()
            # If source and destination shares are placed in a different
            # clusters, we'll need the both vserver peered.
            if src_share_cluster_name != dest_share_cluster_name:
                if not self._get_vserver_peers(dest_vserver, src_vserver):
                    # 3.1. Request vserver peer creation from new_replica's
                    # host to active replica's host
                    dest_share_client.create_vserver_peer(
                        dest_vserver, src_vserver,
                        peer_cluster_name=src_share_cluster_name)

                    # 3.2. Accepts the vserver peering using active replica
                    # host's client
                    src_share_client.accept_vserver_peer(src_vserver,
                                                         dest_vserver)

        return (super(NetAppCmodeMultiSVMFileStorageLibrary, self)
                .create_share_from_snapshot(
                    context, share, snapshot, share_server=share_server,
                    parent_share=parent_share))

    @na_utils.trace
    def _is_share_server_compatible(self, share_server, expected_nfs_config):
        """Check if the share server has the given nfs config

        The None and the default_nfs_config should be considered
        as the same configuration.
        """
        nfs_config = share_server.get('backend_details', {}).get('nfs_config')
        share_server_nfs = jsonutils.loads(nfs_config) if nfs_config else None

        if share_server_nfs == expected_nfs_config:
            return True
        elif (share_server_nfs is None and
              expected_nfs_config == self._default_nfs_config):
            return True
        elif (expected_nfs_config is None and
              share_server_nfs == self._default_nfs_config):
            return True

        return False

    def choose_share_server_compatible_with_share(self, context, share_servers,
                                                  share, snapshot=None,
                                                  share_group=None):
        """Method that allows driver to choose share server for provided share.

        If compatible share-server is not found, method should return None.

        :param context: Current context
        :param share_servers: list with share-server models
        :param share:  share model
        :param snapshot: snapshot model
        :param share_group: ShareGroup model with shares
        :returns: share-server or None
        """
        if not share_servers:
            # No share server to reuse
            return None

        nfs_config = None
        extra_specs = share_types.get_extra_specs_from_share(share)
        if self.is_nfs_config_supported:
            nfs_config = self._get_nfs_config_provisioning_options(extra_specs)

        provisioning_options = self._get_provisioning_options(extra_specs)
        # Get FPolicy extra specs to avoid incompatible share servers
        fpolicy_ext_to_include = provisioning_options.get(
            'fpolicy_extensions_to_include')
        fpolicy_ext_to_exclude = provisioning_options.get(
            'fpolicy_extensions_to_exclude')
        fpolicy_file_operations = provisioning_options.get(
            'fpolicy_file_operations')

        # Avoid the reuse of 'dp_protection' vservers:
        for share_server in share_servers:
            if self._check_reuse_share_server(
                    share_server, nfs_config, share=share,
                    share_group=share_group,
                    fpolicy_ext_include=fpolicy_ext_to_include,
                    fpolicy_ext_exclude=fpolicy_ext_to_exclude,
                    fpolicy_file_operations=fpolicy_file_operations):
                return share_server

        #  There is no compatible share server to be reused
        return None

    @na_utils.trace
    def _check_reuse_share_server(self, share_server, nfs_config, share=None,
                                  share_group=None, fpolicy_ext_include=None,
                                  fpolicy_ext_exclude=None,
                                  fpolicy_file_operations=None):
        """Check whether the share_server can be reused or not."""
        if (share_group and share_group.get('share_server_id') !=
                share_server['id']):
            return False

        backend_name = share_utils.extract_host(share_server['host'],
                                                level='backend_name')
        try:
            vserver_name, client = self._get_vserver(share_server,
                                                     backend_name=backend_name)
        except (exception.InvalidInput,
                exception.VserverNotSpecified,
                exception.VserverNotFound) as error:
            LOG.warning("Could not determine vserver for reuse of "
                        "share server. Share server: %(ss)s - Error: %(err)s",
                        {'ss': share_server, 'err': error})
            return False
        vserver_info = client.get_vserver_info(vserver_name)
        if (vserver_info.get('operational_state') != 'running'
                or vserver_info.get('state') != 'running'
                or vserver_info.get('subtype') != 'default'):
            return False

        if share:
            share_pool = share_utils.extract_host(
                share['host'], level='pool')
            if self._is_flexgroup_pool(share_pool):
                share_pool_list = self._get_flexgroup_aggregate_list(
                    share_pool)
            else:
                share_pool_list = [share_pool]
            aggr_list = client.list_vserver_aggregates()
            if not set(share_pool_list).issubset(set(aggr_list)):
                return False

        if self.is_nfs_config_supported:
            # NOTE(felipe_rodrigues): Do not check that the share nfs_config
            # matches with the group nfs_config, because the API guarantees
            # that the share type is an element of the group types.
            return self._is_share_server_compatible(share_server, nfs_config)

        if fpolicy_ext_include or fpolicy_ext_exclude:
            fpolicies = client.get_fpolicy_policies_status()
            if len(fpolicies) >= self.FPOLICY_MAX_VSERVER_POLICIES:
                # This share server already reached it maximum number of
                # policies, we need to check if we can reuse one, otherwise,
                # it is not suitable for this share.
                reusable_scope = self._find_reusable_fpolicy_scope(
                    share, client,
                    fpolicy_extensions_to_include=fpolicy_ext_include,
                    fpolicy_extensions_to_exclude=fpolicy_ext_exclude,
                    fpolicy_file_operations=fpolicy_file_operations)
                if not reusable_scope:
                    return False

        return True

    @na_utils.trace
    def choose_share_server_compatible_with_share_group(
            self, context, share_servers, share_group_ref,
            share_group_snapshot=None):
        """Choose the server compatible with group.

        If the NFS configuration is supported, it will check that the group
        types agree for the NFS extra-specs values.
        """
        if not share_servers:
            # No share server to reuse
            return None

        nfs_config = None
        if self.is_nfs_config_supported:
            nfs_config = self._get_nfs_config_share_group(share_group_ref)

        # NOTE(dviroel): FPolicy extra-specs won't be conflicting, since
        #  multiple policies can be created. The maximum number of policies or
        #  the reusability of existing ones, can only be analyzed at share
        #  instance creation.
        for share_server in share_servers:
            if self._check_reuse_share_server(share_server, nfs_config):
                return share_server

        return None

    @na_utils.trace
    def _get_nfs_config_share_group(self, share_group_ref):
        """Get the NFS config of the share group.

        In case the group types do not agree for the NFS config, it throws an
        exception.
        """
        nfs_config = None
        first = True
        for st in share_group_ref.get('share_types', []):
            extra_specs = share_types.get_share_type_extra_specs(
                st['share_type_id'])

            if first:
                self._check_nfs_config_extra_specs_validity(extra_specs)
                nfs_config = self._get_nfs_config_provisioning_options(
                    extra_specs)
                first = False
                continue

            type_nfs_config = self._get_nfs_config_provisioning_options(
                extra_specs)
            if nfs_config != type_nfs_config:
                msg = _("The specified share_types cannot have "
                        "conflicting values for the NFS configuration "
                        "extra-specs.")
                raise exception.InvalidInput(reason=msg)

        return nfs_config

    @na_utils.trace
    def manage_existing(self, share, driver_options, share_server=None):

        # In case NFS config is supported, the share's nfs_config must be the
        # same as the server
        if share_server and self.is_nfs_config_supported:
            extra_specs = share_types.get_extra_specs_from_share(share)
            nfs_config = self._get_nfs_config_provisioning_options(extra_specs)
            if not self._is_share_server_compatible(share_server, nfs_config):
                args = {'server_id': share_server['id']}
                msg = _('Invalid NFS configuration for the server '
                        '%(server_id)s . The extra-specs must match the '
                        'values of NFS of the server.')
                raise exception.NetAppException(msg % args)

        return (super(NetAppCmodeMultiSVMFileStorageLibrary, self).
                manage_existing(share, driver_options,
                                share_server=share_server))

    @na_utils.trace
    def _check_compatibility_using_svm_dr(
            self, src_client, dest_client, shares_request_spec, pools):
        """Send a request to pause a migration.

        :param src_client: source cluster client.
        :param dest_client: destination cluster client.
        :param shares_request_spec: shares specifications.
        :param pools: pools to be used during the migration.
        :returns server migration mechanism name and compatibility result
            example: (svm_dr, True).
        """
        method = SERVER_MIGRATE_SVM_DR
        if (not src_client.is_svm_dr_supported()
                or not dest_client.is_svm_dr_supported()):
            msg = _("Cannot perform server migration because at leat one of "
                    "the backends doesn't support SVM DR.")
            LOG.error(msg)
            return method, False

        # Check that server does not have any FlexGroup volume.
        if src_client.is_flexgroup_supported():
            dm_session = data_motion.DataMotionSession()
            for req_spec in shares_request_spec.get('shares_req_spec', []):
                share_instance = req_spec.get('share_instance_properties', {})
                host = share_instance.get('host')
                if self.is_flexgroup_destination_host(host, dm_session):
                    msg = _("Cannot perform server migration since a "
                            "FlexGroup was encountered in share server to be "
                            "migrated.")
                    LOG.error(msg)
                    return method, False

        # Check capacity.
        server_total_size = (shares_request_spec.get('shares_size', 0) +
                             shares_request_spec.get('snapshots_size', 0))
        # NOTE(dviroel): If the backend has a 'max_over_subscription_ratio'
        # configured and greater than 1, we'll consider thin provisioning
        # enable for all shares.
        thin_provisioning = self.configuration.max_over_subscription_ratio > 1
        if self.configuration.netapp_server_migration_check_capacity is True:
            if not self._check_capacity_compatibility(pools, thin_provisioning,
                                                      server_total_size):
                msg = _("Cannot perform server migration because destination "
                        "host doesn't have enough free space.")
                LOG.error(msg)
                return method, False
        return method, True

    @na_utils.trace
    def _get_job_uuid(self, job):
        """Get the uuid of a job."""
        job = job.get("job", {})
        return job.get("uuid")

    @na_utils.trace
    def _wait_for_operation_status(
            self, operation_id, func_get_operation, desired_status='success',
            timeout=None):
        """Waits until a given operation reachs the desired status.

        :param operation_id: ID of the operation to be searched.
        :param func_get_operation: Function to be used to get the operation
            details.
        :param desired_status: Operation expected status.
        :param timeout: How long (in seconds) should the driver wait for the
            status to be reached.

        """
        if not timeout:
            timeout = (
                self.configuration.netapp_server_migration_state_change_timeout
            )
        interval = 10
        retries = int(timeout / interval) or 1

        @utils.retry(exception.ShareBackendException, interval=interval,
                     retries=retries, backoff_rate=1)
        def wait_for_status():
            # Get the job based on its id.
            operation = func_get_operation(operation_id)
            status = operation.get("status") or operation.get("state")

            if status != desired_status:
                msg = _(
                    "Operation %(operation_id)s didn't reach status "
                    "%(desired_status)s. Current status is %(status)s.") % {
                    'operation_id': operation_id,
                    'desired_status': desired_status,
                    'status': status
                }
                LOG.debug(msg)

                # Failed, no need to retry.
                if status == 'error':
                    msg = _('Operation %(operation_id)s is in error status.'
                            'Reason: %(message)s')
                    raise exception.NetAppException(
                        msg % {'operation_id': operation_id,
                               'message': operation.get('message')})

                # Didn't fail, so we can retry.
                raise exception.ShareBackendException(msg)

            elif status == desired_status:
                msg = _(
                    'Operation %(operation_id)s reached status %(status)s.')
                LOG.debug(
                    msg, {'operation_id': operation_id, 'status': status})
                return
        try:
            wait_for_status()
        except exception.NetAppException:
            raise
        except exception.ShareBackendException:
            msg_args = {'operation_id': operation_id, 'status': desired_status}
            msg = _('Timed out while waiting for operation %(operation_id)s '
                    'to reach status %(status)s') % msg_args
            raise exception.NetAppException(msg)

    @na_utils.trace
    def _check_compatibility_for_svm_migrate(
            self, source_cluster_name, source_share_server_name,
            source_share_server, dest_aggregates, dest_client):
        """Checks if the migration can be performed using SVM Migrate.

        1. Send the request to the backed to check if the migration is possible
        2. Wait until the job finishes checking the migration status
        """

        # Reuse network information from the source share server in the SVM
        # Migrate if the there was no share network changes.
        network_info = {
            'network_allocations':
                source_share_server['network_allocations'],
            'neutron_subnet_id':
                source_share_server['share_network_subnets'][0].get(
                    'neutron_subnet_id')
        }

        # 2. Create new ipspace, port and broadcast domain.
        node_name = self._client.list_cluster_nodes()[0]
        port = self._get_node_data_port(node_name)
        vlan = network_info['network_allocations'][0]['segmentation_id']
        destination_ipspace = self._client.get_ipspace_name_for_vlan_port(
            node_name, port, vlan) or self._create_ipspace(
            network_info, client=dest_client)
        self._create_port_and_broadcast_domain(
            destination_ipspace, network_info)

        def _cleanup_ipspace(ipspace):
            try:
                dest_client.delete_ipspace(ipspace)
            except Exception:
                LOG.info(
                    'Did not delete ipspace used to check the compatibility '
                    'for SVM Migrate. It is possible that it was reused and '
                    'there are other entities consuming it.')

        # 1. Sends the request to the backend.
        try:
            job = dest_client.svm_migration_start(
                source_cluster_name, source_share_server_name, dest_aggregates,
                dest_ipspace=destination_ipspace, check_only=True)
        except Exception:
            LOG.error('Failed to check compatibility for migration.')
            _cleanup_ipspace(destination_ipspace)
            raise

        job_id = self._get_job_uuid(job)

        try:
            # 2. Wait until the job to check the migration status concludes.
            self._wait_for_operation_status(
                job_id, dest_client.get_migration_check_job_state)
            _cleanup_ipspace(destination_ipspace)
            return True
        except exception.NetAppException:
            # Performed the check with the given parameters and the backend
            # returned an error, so the migration is not compatible
            _cleanup_ipspace(destination_ipspace)
            return False

    @na_utils.trace
    def _check_for_migration_support(
            self, src_client, dest_client, source_share_server,
            shares_request_spec, src_cluster_name, pools):
        """Checks if the migration is supported and chooses the way to do it

        In terms of performance, SVM Migrate is more adequate and it should
        be prioritised over a SVM DR migration. If both source and destination
        clusters do not support SVM Migrate, then SVM DR is the option to be
        used.
        1. Checks if both source and destination clients support SVM Migrate.
        2. Requests the migration.
        """

        # 1. Checks if both source and destination clients support SVM Migrate.
        if (dest_client.is_svm_migrate_supported()
                and src_client.is_svm_migrate_supported()):
            source_share_server_name = self._get_vserver_name(
                source_share_server['id'])

            # Check if the migration is supported.
            try:
                result = self._check_compatibility_for_svm_migrate(
                    src_cluster_name, source_share_server_name,
                    source_share_server, self._find_matching_aggregates(),
                    dest_client)
                return SERVER_MIGRATE_SVM_MIGRATE, result
            except Exception:
                LOG.error('Failed to check the compatibility for the share '
                          'server migration using SVM Migrate.')
                return SERVER_MIGRATE_SVM_MIGRATE, False

        # SVM Migrate is not supported, try to check the compatibility using
        # SVM DR.
        return self._check_compatibility_using_svm_dr(
            src_client, dest_client, shares_request_spec, pools)

    @na_utils.trace
    def share_server_migration_check_compatibility(
            self, context, source_share_server, dest_host, old_share_network,
            new_share_network, shares_request_spec):

        not_compatible = {
            'compatible': False,
            'writable': None,
            'nondisruptive': None,
            'preserve_snapshots': None,
            'migration_cancel': None,
            'migration_get_progress': None,
            'share_network_id': None,
        }

        # We need cluster creds, of course
        if not self._have_cluster_creds:
            msg = _("Cluster credentials have not been configured with this "
                    "share driver. Cannot perform server migration operation.")
            LOG.error(msg)
            return not_compatible

        # Vserver will spread across aggregates in this implementation
        if share_utils.extract_host(dest_host, level='pool') is not None:
            msg = _("Cannot perform server migration to a specific pool. "
                    "Please choose a destination host 'host@backend' as "
                    "destination.")
            LOG.error(msg)
            return not_compatible

        src_backend_name = share_utils.extract_host(
            source_share_server['host'], level='backend_name')
        src_vserver, src_client = self._get_vserver(
            source_share_server, backend_name=src_backend_name)
        dest_backend_name = share_utils.extract_host(dest_host,
                                                     level='backend_name')
        # Block migration within the same backend.
        if src_backend_name == dest_backend_name:
            msg = _("Cannot perform server migration within the same backend. "
                    "Please choose a destination host different from the "
                    "source.")
            LOG.error(msg)
            return not_compatible

        src_cluster_name = src_client.get_cluster_name()
        # NOTE(dviroel): This call is supposed to made in the destination host
        dest_cluster_name = self._client.get_cluster_name()
        # Must be in different clusters too, SVM-DR restriction
        if src_cluster_name == dest_cluster_name:
            msg = _("Cannot perform server migration within the same cluster. "
                    "Please choose a destination host that's in a different "
                    "cluster.")
            LOG.error(msg)
            return not_compatible

        # Blocking multiple subnets
        new_subnets = new_share_network.get('share_network_subnets', [])
        old_subnets = old_share_network.get('share_network_subnets', [])
        if (len(new_subnets) != 1) or (len(old_subnets) != 1):
            msg = _("Cannot perform server migration for share network"
                    "with multiple subnets.")
            LOG.error(msg)
            return not_compatible

        pools = self._get_pools()

        # NOTE(dviroel): These clients can only be used for non-tunneling
        # requests.
        dst_client = data_motion.get_client_for_backend(dest_backend_name,
                                                        vserver_name=None)

        migration_method, compatibility = self._check_for_migration_support(
            src_client, dst_client, source_share_server, shares_request_spec,
            src_cluster_name, pools)

        if not compatibility:
            return not_compatible

        # Blocking different security services for now
        if old_share_network['id'] != new_share_network['id']:
            new_sec_services = new_share_network.get('security_services', [])
            old_sec_services = old_share_network.get('security_services', [])
            if new_sec_services or old_sec_services:
                new_sec_serv_ids = [ss['id'] for ss in new_sec_services]
                old_sec_serv_ids = [ss['id'] for ss in old_sec_services]
                if not set(new_sec_serv_ids) == set(old_sec_serv_ids):
                    msg = _("Cannot perform server migration for different "
                            "security services. Please choose a suitable "
                            "share network that matches the source security "
                            "service.")
                    LOG.error(msg)
                    return not_compatible

        # Check 'netapp_flexvol_encryption' and 'revert_to_snapshot_support'
        specs_to_validate = ('netapp_flexvol_encryption',
                             'revert_to_snapshot_support')
        for req_spec in shares_request_spec.get('shares_req_spec', []):
            extra_specs = req_spec.get('share_type', {}).get('extra_specs', {})
            for spec in specs_to_validate:
                if extra_specs.get(spec) and not pools[0][spec]:
                    msg = _("Cannot perform server migration since the "
                            "destination host doesn't support the required "
                            "extra-spec %s.") % spec
                    LOG.error(msg)
                    return not_compatible
            # TODO(dviroel): disk_type extra-spec

        nondisruptive = (migration_method == SERVER_MIGRATE_SVM_MIGRATE)

        compatibility = {
            'compatible': True,
            'writable': True,
            'nondisruptive': nondisruptive,
            'preserve_snapshots': True,
            'share_network_id': new_share_network['id'],
            'migration_cancel': True,
            'migration_get_progress': False,
        }

        return compatibility

    @na_utils.trace
    def _migration_start_using_svm_dr(
            self, source_share_server, dest_share_server):
        """Start share server migration using SVM DR.

        1. Create vserver peering between source and destination
        2. Create SnapMirror
        """
        src_backend_name = share_utils.extract_host(
            source_share_server['host'], level='backend_name')
        src_vserver, src_client = self._get_vserver(
            share_server=source_share_server, backend_name=src_backend_name)
        src_cluster = src_client.get_cluster_name()

        dest_backend_name = share_utils.extract_host(
            dest_share_server['host'], level='backend_name')
        dest_vserver, dest_client = self._get_vserver(
            share_server=dest_share_server, backend_name=dest_backend_name)
        dest_cluster = dest_client.get_cluster_name()

        # 1. Check and create vserver peer if needed
        if not self._get_vserver_peers(dest_vserver, src_vserver):
            # Request vserver peer creation from destination to source
            # NOTE(dviroel): vserver peering rollback is handled by
            # '_delete_vserver' function.
            dest_client.create_vserver_peer(
                dest_vserver, src_vserver,
                peer_cluster_name=src_cluster)

            # Accepts the vserver peering using active replica host's
            # client (inter-cluster only)
            if dest_cluster != src_cluster:
                src_client.accept_vserver_peer(src_vserver, dest_vserver)

        # 2. Create SnapMirror
        dm_session = data_motion.DataMotionSession()
        try:
            dm_session.create_snapmirror_svm(source_share_server,
                                             dest_share_server)
        except Exception:
            # NOTE(dviroel): vserver peer delete will be handled on vserver
            # teardown
            dm_session.cancel_snapmirror_svm(source_share_server,
                                             dest_share_server)
            msg_args = {
                'src': source_share_server['id'],
                'dest': dest_share_server['id'],
            }
            msg = _('Could not initialize SnapMirror between %(src)s and '
                    '%(dest)s vservers.') % msg_args
            raise exception.NetAppException(message=msg)
        return None

    @na_utils.trace
    def _migration_start_using_svm_migrate(
            self, context, source_share_server, dest_share_server, src_client,
            dest_client):
        """Start share server migration using SVM Migrate.

        1. Check if share network reusage is supported
        2. Create a new ipspace, port and broadcast domain to the dest server
        3. Send the request start the share server migration
        4. Read the job id and get the id of the migration
        5. Set the migration uuid in the backend details
        """

        # 1. Check if share network reusage is supported
        # NOTE(carloss): if share network was not changed, SVM migrate can
        # reuse the network allocation from the source share server, so as
        # Manila haven't made new allocations, we can just get allocation data
        # from the source share server.
        if not dest_share_server['network_allocations']:
            share_server_network_info = source_share_server
        else:
            share_server_network_info = dest_share_server

        # Reuse network information from the source share server in the SVM
        # Migrate if the there was no share network changes.
        network_info = {
            'network_allocations':
                share_server_network_info['network_allocations'],
            'neutron_subnet_id':
                share_server_network_info['share_network_subnets'][0].get(
                    'neutron_subnet_id')
        }

        # 2. Create new ipspace, port and broadcast domain.
        node_name = self._client.list_cluster_nodes()[0]
        port = self._get_node_data_port(node_name)
        vlan = network_info['network_allocations'][0]['segmentation_id']
        destination_ipspace = self._client.get_ipspace_name_for_vlan_port(
            node_name, port, vlan) or self._create_ipspace(
            network_info, client=dest_client)
        self._create_port_and_broadcast_domain(
            destination_ipspace, network_info)

        # Prepare the migration request.
        src_cluster_name = src_client.get_cluster_name()
        source_share_server_name = self._get_vserver_name(
            source_share_server['id'])

        # 3. Send the migration request to ONTAP.
        try:
            result = dest_client.svm_migration_start(
                src_cluster_name, source_share_server_name,
                self._find_matching_aggregates(),
                dest_ipspace=destination_ipspace)

            # 4. Read the job id and get the id of the migration.
            result_job = result.get("job", {})
            job_details = dest_client.get_job(result_job.get("uuid"))
            job_description = job_details.get('description')
            migration_uuid = job_description.split('/')[-1]
        except Exception:
            # As it failed, we must remove the ipspace, ports and broadcast
            # domain.
            dest_client.delete_ipspace(destination_ipspace)

            msg = _("Unable to start the migration for share server %s."
                    % source_share_server['id'])
            raise exception.NetAppException(msg)

        # 5. Returns migration data to be saved as backend details.
        server_info = {
            "backend_details": {
                na_utils.MIGRATION_OPERATION_ID_KEY: migration_uuid
            }
        }
        return server_info

    @na_utils.trace
    def share_server_migration_start(
            self, context, source_share_server, dest_share_server,
            share_intances, snapshot_instances):
        """Start share server migration.

        This method will choose the best migration strategy to perform the
        migration, based on the storage functionalities support.
        """
        src_backend_name = share_utils.extract_host(
            source_share_server['host'], level='backend_name')
        dest_backend_name = share_utils.extract_host(
            dest_share_server['host'], level='backend_name')
        dest_client = data_motion.get_client_for_backend(
            dest_backend_name, vserver_name=None)
        __, src_client = self._get_vserver(
            share_server=source_share_server, backend_name=src_backend_name)

        use_svm_migrate = (
            src_client.is_svm_migrate_supported()
            and dest_client.is_svm_migrate_supported())

        if use_svm_migrate:
            result = self._migration_start_using_svm_migrate(
                context, source_share_server, dest_share_server, src_client,
                dest_client)
        else:
            result = self._migration_start_using_svm_dr(
                source_share_server, dest_share_server)

        msg_args = {
            'src': source_share_server['id'],
            'dest': dest_share_server['id'],
            'migration_method': 'SVM Migrate' if use_svm_migrate else 'SVM DR'
        }
        msg = _('Starting share server migration from %(src)s to %(dest)s '
                'using %(migration_method)s as migration method.')
        LOG.info(msg, msg_args)

        return result

    def _get_snapmirror_svm(self, source_share_server, dest_share_server):
        dm_session = data_motion.DataMotionSession()
        try:
            snapmirrors = dm_session.get_snapmirrors_svm(
                source_share_server, dest_share_server)
        except netapp_api.NaApiError:
            msg_args = {
                'src': source_share_server['id'],
                'dest': dest_share_server['id']
            }
            msg = _("Could not retrieve snapmirrors between source "
                    "%(src)s and destination %(dest)s vServers.") % msg_args
            LOG.exception(msg)
            raise exception.NetAppException(message=msg)

        return snapmirrors

    @na_utils.trace
    def _share_server_migration_continue_svm_dr(
            self, source_share_server, dest_share_server):
        """Continues a share server migration using SVM DR."""
        snapmirrors = self._get_snapmirror_svm(source_share_server,
                                               dest_share_server)
        if not snapmirrors:
            msg_args = {
                'src': source_share_server['id'],
                'dest': dest_share_server['id']
            }
            msg = _("No snapmirror relationship was found between source "
                    "%(src)s and destination %(dest)s vServers.") % msg_args
            LOG.exception(msg)
            raise exception.NetAppException(message=msg)

        snapmirror = snapmirrors[0]
        in_progress_status = ['preparing', 'transferring', 'finalizing']
        mirror_state = snapmirror.get('mirror-state')
        status = snapmirror.get('relationship-status')
        if mirror_state != 'snapmirrored' and status in in_progress_status:
            LOG.debug("Data transfer still in progress.")
            return False
        elif mirror_state == 'snapmirrored' and status == 'idle':
            LOG.info("Source and destination vServers are now snapmirrored.")
            return True

        msg = _("Snapmirror is not ready yet. The current mirror state is "
                "'%(mirror_state)s' and relationship status is '%(status)s'.")
        msg_args = {
            'mirror_state': mirror_state,
            'status': status,
        }
        LOG.debug(msg, msg_args)
        return False

    @na_utils.trace
    def _share_server_migration_continue_svm_migrate(self, dest_share_server,
                                                     migration_id):
        """Continues the migration for a share server.

        :param dest_share_server: reference for the destination share server.
        :param migration_id: ID of the migration.
        """
        dest_client = data_motion.get_client_for_host(
            dest_share_server['host'])
        try:
            result = dest_client.svm_migration_get(migration_id)
        except netapp_api.NaApiError as e:
            msg = (_('Failed to continue the migration for share server '
                     '%(server_id)s. Reason: %(reason)s'
                     ) % {'server_id': dest_share_server['id'],
                          'reason': e.message}
                   )
            raise exception.NetAppException(message=msg)
        return (
            result.get("state") == na_utils.MIGRATION_STATE_READY_FOR_CUTOVER)

    @na_utils.trace
    def share_server_migration_continue(self, context, source_share_server,
                                        dest_share_server, share_instances,
                                        snapshot_instances):
        """Continues the migration of a share server."""
        # If the migration operation was started using SVM migrate, it
        # returned a migration ID to get information about the job afterwards.
        migration_id = self._get_share_server_migration_id(
            dest_share_server)

        # Checks the progress for a SVM migrate migration.
        if migration_id:
            return self._share_server_migration_continue_svm_migrate(
                dest_share_server, migration_id)

        # Checks the progress of a SVM DR Migration.
        return self._share_server_migration_continue_svm_dr(
            source_share_server, dest_share_server)

    def _setup_networking_for_destination_vserver(
            self, vserver_client, vserver_name, new_net_allocations):
        ipspace_name = vserver_client.get_vserver_ipspace(vserver_name)

        # NOTE(dviroel): Security service and NFS configuration should be
        # handled by SVM DR, so no changes will be made here.
        vlan = new_net_allocations[0]['segmentation_id']

        @utils.synchronized('netapp-VLAN-%s' % vlan, external=True)
        def setup_network_for_destination_vserver():
            self._setup_network_for_vserver(
                vserver_name, vserver_client, new_net_allocations,
                ipspace_name,
                enable_nfs=False,
                security_services=None)

        setup_network_for_destination_vserver()

    @na_utils.trace
    def _share_server_migration_complete_svm_dr(
            self, source_share_server, dest_share_server, src_vserver,
            src_client, share_instances, new_net_allocations):
        """Perform steps to complete the SVM DR migration.

        1. Do a last SnapMirror update.
        2. Quiesce, abort and then break the relationship.
        3. Stop the source vserver
        4. Configure network interfaces in the destination vserver
        5. Start the destinarion vserver
        6. Delete and release the snapmirror
        """
        dest_backend_name = share_utils.extract_host(
            dest_share_server['host'], level='backend_name')
        dest_vserver, dest_client = self._get_vserver(
            share_server=dest_share_server, backend_name=dest_backend_name)

        dm_session = data_motion.DataMotionSession()
        try:
            # 1. Start an update to try to get a last minute transfer before we
            # quiesce and break
            dm_session.update_snapmirror_svm(source_share_server,
                                             dest_share_server)
        except exception.StorageCommunicationException:
            # Ignore any errors since the current source may be unreachable
            pass

        try:
            # 2. Attempt to quiesce, abort and then break SnapMirror
            dm_session.quiesce_and_break_snapmirror_svm(source_share_server,
                                                        dest_share_server)
            # NOTE(dviroel): Lets wait until the destination vserver be
            # promoted to 'default' and state 'running', before starting
            # shutting down the source
            dm_session.wait_for_vserver_state(
                dest_vserver, dest_client, subtype='default',
                state='running', operational_state='stopped',
                timeout=(self.configuration.
                         netapp_server_migration_state_change_timeout))

            # 3. Stop source vserver
            src_client.stop_vserver(src_vserver)

            # 4. Setup network configuration
            self._setup_networking_for_destination_vserver(
                dest_client, dest_vserver, new_net_allocations)

            # 5. Start the destination.
            dest_client.start_vserver(dest_vserver)

        except Exception:
            # Try to recover source vserver
            try:
                src_client.start_vserver(src_vserver)
            except Exception:
                LOG.warning("Unable to recover source share server after a "
                            "migration failure.")
            # Destroy any snapmirror and make destination vserver to have its
            # subtype set to 'default'
            dm_session.cancel_snapmirror_svm(source_share_server,
                                             dest_share_server)
            # Rollback resources transferred to the destination
            for instance in share_instances:
                self._delete_share(instance, dest_vserver, dest_client,
                                   remove_export=False)

            msg_args = {
                'src': source_share_server['id'],
                'dest': dest_share_server['id'],
            }
            msg = _('Could not complete the migration between %(src)s and '
                    '%(dest)s vservers.') % msg_args
            raise exception.NetAppException(message=msg)

        # 6. Delete/release snapmirror
        dm_session.delete_snapmirror_svm(source_share_server,
                                         dest_share_server)

    @na_utils.trace
    def _share_server_migration_complete_svm_migrate(
            self, migration_id, dest_share_server):
        """Completes share server migration using SVM Migrate.

        1. Call functions to conclude the migration for SVM Migrate
        2. Waits until the job gets a success status
        3. Wait until the migration cancellation reach the desired status
        """
        dest_client = data_motion.get_client_for_host(
            dest_share_server['host'])

        try:
            # Triggers the migration completion.
            job = dest_client.svm_migrate_complete(migration_id)
            job_id = self._get_job_uuid(job)

            # Wait until the job is successful.
            self._wait_for_operation_status(
                job_id, dest_client.get_job)

            # Wait until the migration is entirely finished.
            self._wait_for_operation_status(
                migration_id, dest_client.svm_migration_get,
                desired_status=na_utils.MIGRATION_STATE_MIGRATE_COMPLETE)
        except exception.NetAppException:
            msg = _(
                "Failed to complete the migration for "
                "share server %s.") % dest_share_server['id']
            raise exception.NetAppException(msg)

    @na_utils.trace
    def share_server_migration_complete(self, context, source_share_server,
                                        dest_share_server, share_instances,
                                        snapshot_instances, new_network_alloc):
        """Completes share server migration.

        1. Call functions to conclude the migration for SVM DR or SVM Migrate
        2. Build the list of export_locations for each share
        3. Release all resources from the source share server
        """
        src_backend_name = share_utils.extract_host(
            source_share_server['host'], level='backend_name')
        src_vserver, src_client = self._get_vserver(
            share_server=source_share_server, backend_name=src_backend_name)
        dest_backend_name = share_utils.extract_host(
            dest_share_server['host'], level='backend_name')

        migration_id = self._get_share_server_migration_id(dest_share_server)

        share_server_to_get_vserver_name_from = (
            source_share_server if migration_id else dest_share_server)

        dest_vserver, dest_client = self._get_vserver(
            share_server=share_server_to_get_vserver_name_from,
            backend_name=dest_backend_name)

        server_backend_details = {}
        # 1. Call functions to conclude the migration for SVM DR or SVM
        # Migrate.
        if migration_id:
            self._share_server_migration_complete_svm_migrate(
                migration_id, dest_share_server)

            server_backend_details = source_share_server['backend_details']

            # If there are new network allocations to be added, do so, and add
            # them to the share server's backend details.
            if dest_share_server['network_allocations']:
                # Teardown the current network allocations
                current_network_interfaces = (
                    dest_client.list_network_interfaces())

                # Need a cluster client to be able to remove the current
                # network interfaces
                dest_cluster_client = data_motion.get_client_for_host(
                    dest_share_server['host'])
                for interface_name in current_network_interfaces:
                    dest_cluster_client.delete_network_interface(
                        src_vserver, interface_name)
                self._setup_networking_for_destination_vserver(
                    dest_client, src_vserver, new_network_alloc)

                server_backend_details.pop('ports')
                ports = {}
                for allocation in dest_share_server['network_allocations']:
                    ports[allocation['id']] = allocation['ip_address']
                server_backend_details['ports'] = jsonutils.dumps(ports)
        else:
            self._share_server_migration_complete_svm_dr(
                source_share_server, dest_share_server, src_vserver,
                src_client, share_instances, new_network_alloc)

        # 2. Build a dict with shares/snapshot location updates.
        # NOTE(dviroel): For SVM DR, the share names aren't modified, only the
        # export_locations are updated due to network changes.
        share_updates = {}
        for instance in share_instances:
            # Get the volume to find out the associated aggregate
            # Update post-migration info that can't be replicated
            try:
                share_name = self._get_backend_share_name(instance['id'])
                volume = dest_client.get_volume(share_name)
                dest_aggregate = volume.get('aggregate')

                if not migration_id:
                    # Update share attributes according with share extra specs.
                    self._update_share_attributes_after_server_migration(
                        instance, src_client, dest_aggregate, dest_client)

            except Exception:
                msg_args = {
                    'src': source_share_server['id'],
                    'dest': dest_share_server['id'],
                }
                msg = _('Could not complete the migration between %(src)s and '
                        '%(dest)s vservers. One of the shares was not found '
                        'in the destination vserver.') % msg_args
                raise exception.NetAppException(message=msg)

            new_share_data = {
                'pool_name': volume.get('aggregate')
            }

            share_host = instance['host']

            # If using SVM migrate, must already ensure the export policies
            # using the new host information.
            if migration_id:
                old_aggregate = share_host.split('#')[1]
                share_host = share_host.replace(
                    old_aggregate, dest_aggregate)

            export_locations = self._create_export(
                instance, dest_share_server, dest_vserver, dest_client,
                clear_current_export_policy=False,
                ensure_share_already_exists=True,
                share_host=share_host)
            new_share_data.update({'export_locations': export_locations})

            share_updates.update({instance['id']: new_share_data})

        # NOTE(dviroel): Nothing to update in snapshot instances since the
        # provider location didn't change.

        # NOTE(carloss): as SVM DR works like a replica, we must delete the
        # source shares after the migration. In case of SVM Migrate, the shares
        # were moved to the destination, so there's no need to remove them.
        # Then, we need to delete the source server
        if not migration_id:
            # 3. Release source share resources.
            for instance in share_instances:
                self._delete_share(instance, src_vserver, src_client,
                                   remove_export=True)

        # NOTE(dviroel): source share server deletion must be triggered by
        # the manager after finishing the migration
        LOG.info('Share server migration completed.')
        return {
            'share_updates': share_updates,
            'server_backend_details': server_backend_details
        }

    @na_utils.trace
    def _get_share_server_migration_id(self, dest_share_server):
        return dest_share_server['backend_details'].get(
            na_utils.MIGRATION_OPERATION_ID_KEY)

    @na_utils.trace
    def _migration_cancel_using_svm_dr(
            self, source_share_server, dest_share_server, shares):
        """Cancel a share server migration that is using SVM DR."""
        dm_session = data_motion.DataMotionSession()
        dest_backend_name = share_utils.extract_host(dest_share_server['host'],
                                                     level='backend_name')
        dest_vserver, dest_client = self._get_vserver(
            share_server=dest_share_server, backend_name=dest_backend_name)

        try:
            snapmirrors = self._get_snapmirror_svm(source_share_server,
                                                   dest_share_server)
            if snapmirrors:
                dm_session.cancel_snapmirror_svm(source_share_server,
                                                 dest_share_server)
            # Do a simple volume cleanup in the destination vserver
            for instance in shares:
                self._delete_share(instance, dest_vserver, dest_client,
                                   remove_export=False)

        except Exception:
            msg_args = {
                'src': source_share_server['id'],
                'dest': dest_share_server['id'],
            }
            msg = _('Unable to cancel SnapMirror relationship between %(src)s '
                    'and %(dest)s vservers.') % msg_args
            raise exception.NetAppException(message=msg)

    @na_utils.trace
    def _migration_cancel_using_svm_migrate(self, migration_id,
                                            dest_share_server):
        """Cancel a share server migration that is using SVM migrate.

        1. Gets information about the migration
        2. Pauses the migration, as it can't be cancelled without pausing
        3. Ask to ONTAP to actually cancel the migration
        """

        # 1. Gets information about the migration.
        dest_client = data_motion.get_client_for_host(
            dest_share_server['host'])
        migration_information = dest_client.svm_migration_get(migration_id)

        # Gets the ipspace that was created so we can delete it if it's not
        # being used anymore.
        dest_ipspace_name = (
            migration_information["destination"]["ipspace"]["name"])

        # 2. Pauses the migration.
        try:
            # Request the migration to be paused and wait until the job is
            # successful.
            job = dest_client.svm_migrate_pause(migration_id)
            job_id = self._get_job_uuid(job)
            self._wait_for_operation_status(job_id, dest_client.get_job)

            # Wait until the migration get actually paused.
            self._wait_for_operation_status(
                migration_id, dest_client.svm_migration_get,
                desired_status=na_utils.MIGRATION_STATE_MIGRATE_PAUSED)
        except exception.NetAppException:
            msg = _("Failed to pause the share server migration.")
            raise exception.NetAppException(message=msg)

        try:
            # 3. Ask to ONTAP to actually cancel the migration.
            job = dest_client.svm_migrate_cancel(migration_id)
            job_id = self._get_job_uuid(job)
            self._wait_for_operation_status(
                job_id, dest_client.get_job)
        except exception.NetAppException:
            msg = _("Failed to cancel the share server migration.")
            raise exception.NetAppException(message=msg)

        # If there is need to, remove the ipspace.
        if (dest_ipspace_name and dest_ipspace_name not in CLUSTER_IPSPACES
                and not dest_client.ipspace_has_data_vservers(
                    dest_ipspace_name)):
            dest_client.delete_ipspace(dest_ipspace_name)
        return

    @na_utils.trace
    def share_server_migration_cancel(self, context, source_share_server,
                                      dest_share_server, shares, snapshots):
        """Send the request to cancel the SVM migration."""

        migration_id = self._get_share_server_migration_id(dest_share_server)

        if migration_id:
            return self._migration_cancel_using_svm_migrate(
                migration_id, dest_share_server)

        self._migration_cancel_using_svm_dr(
            source_share_server, dest_share_server, shares)

        LOG.info('Share server migration was cancelled.')

    @na_utils.trace
    def share_server_migration_get_progress(self, context, src_share_server,
                                            dest_share_server, shares,
                                            snapshots):
        """Compare source SVM total shares size with the destination SVM.

        1. Gets the total size of the source SVM shares
        2. Gets the total size of the destination SVM shares
        3. Return the progress up to 99%, because 100% migration will be
        returned when SVM migration phase 1 is finished.
        """

        # Get the total size of the source share server shares.
        src_shares_total_size = 0
        for instance in shares:
            src_shares_total_size = (
                src_shares_total_size + instance.get('size', 0))

        if src_shares_total_size > 0:
            # Destination share server has the same name as the source share
            # server.
            dest_share_server_name = self._get_vserver_name(
                dest_share_server['source_share_server_id'])

            # Get current volume total size in the destination SVM.
            dest_shares_total_size = self._client.get_svm_volumes_total_size(
                dest_share_server_name)

            # The 100% progress will be return only when the SVM migration
            # phase 1 is completed. 99% is an arbitrary number.
            total_progress = (
                (99 * dest_shares_total_size) / src_shares_total_size)

            return {'total_progress': round(total_progress)}

        return {'total_progress': 0}

    def _update_share_attributes_after_server_migration(
            self, src_share_instance, src_client, dest_aggregate, dest_client):
        """Updates destination share instance with share type extra specs."""
        extra_specs = share_types.get_extra_specs_from_share(
            src_share_instance)
        provisioning_options = self._get_provisioning_options(extra_specs)
        volume_name = self._get_backend_share_name(src_share_instance['id'])
        # NOTE(dviroel): Need to retrieve current autosize attributes since
        # they aren't being updated by SVM DR.
        autosize_attrs = src_client.get_volume_autosize_attributes(volume_name)
        # NOTE(dviroel): In order to modify maximum and minimum size, we must
        # convert from Kbytes to bytes.
        for key in ('minimum-size', 'maximum-size'):
            autosize_attrs[key] = int(autosize_attrs[key]) * units.Ki
        provisioning_options['autosize_attributes'] = autosize_attrs
        # NOTE(dviroel): SVM DR already creates a copy of the snapshot policies
        # at the destination, using a different name. If we update the snapshot
        # policy in these volumes, might end up with an error if the policy
        # still does not exist in the destination cluster. Administrators will
        # have the opportunity to add the snapshot policy after a successful
        # migration.
        provisioning_options.pop('snapshot_policy', None)

        # Modify volume to match extra specs
        dest_client.modify_volume(dest_aggregate, volume_name,
                                  **provisioning_options)

    def validate_provisioning_options_for_share(self, provisioning_options,
                                                extra_specs=None,
                                                qos_specs=None):
        if provisioning_options.get('adaptive_qos_policy_group') is not None:
            msg = _("The extra spec 'adaptive_qos_policy_group' is not "
                    "supported by backends configured with "
                    "'driver_handles_share_server' == True mode.")
            raise exception.NetAppException(msg)

        (super(NetAppCmodeMultiSVMFileStorageLibrary, self)
            .validate_provisioning_options_for_share(provisioning_options,
                                                     extra_specs=extra_specs,
                                                     qos_specs=qos_specs))

    def _get_different_keys_for_equal_ss_type(self, current_sec_service,
                                              new_sec_service):
        different_keys = []

        valid_keys = ['dns_ip', 'server', 'domain', 'user', 'password',
                      'ou', 'default_ad_site']
        for key, value in current_sec_service.items():
            if (current_sec_service[key] != new_sec_service[key]
                    and key in valid_keys):
                different_keys.append(key)

        return different_keys

    def _is_security_service_valid(self, security_service):
        mandatory_params = {
            'ldap': ['user', 'password'],
            'active_directory': ['dns_ip', 'domain', 'user', 'password'],
            'kerberos': ['dns_ip', 'domain', 'user', 'password', 'server'],
        }
        ss_type = security_service['type']
        if ss_type == 'ldap':
            ad_domain = security_service.get('domain')
            ldap_servers = security_service.get('server')
            if not bool(ad_domain) ^ bool(ldap_servers):
                msg = _("LDAP security service must have either 'server' or "
                        "'domain' parameters. Use 'server' for Linux/Unix "
                        "LDAP servers or 'domain' for Active Directory LDAP "
                        "server.")
                LOG.error(msg)
                return False

        if ss_type == 'active_directory':
            server = security_service.get('server')
            default_ad_site = security_service.get('default_ad_site')
            if server and default_ad_site:
                msg = _("Active directory security service must not have "
                        "both 'server' and 'default_ad_site' parameters.")
                LOG.error(msg)
                return False

        if not all([security_service[key] is not None
                    for key in mandatory_params[ss_type]]):
            msg = _("The security service %s does not have all the "
                    "parameters needed to used by the share driver."
                    ) % security_service['id']
            LOG.error(msg)
            return False

        return True

    def update_share_server_security_service(self, context, share_server,
                                             network_info,
                                             new_security_service,
                                             current_security_service=None):
        current_type = (
            current_security_service['type'].lower()
            if current_security_service else '')
        new_type = new_security_service['type'].lower()

        vserver_name, vserver_client = self._get_vserver(
            share_server=share_server)

        # Check if this update is supported by our driver
        if not self.check_update_share_server_security_service(
                context, share_server, network_info, new_security_service,
                current_security_service=current_security_service):
            msg = _("The requested security service update is not supported "
                    "by the NetApp driver.")
            LOG.error(msg)
            raise exception.NetAppException(msg)

        if current_security_service is None:
            self._client.setup_security_services([new_security_service],
                                                 vserver_client,
                                                 vserver_name)
            LOG.info("A new security service configuration was added to share "
                     "server '%(share_server_id)s'",
                     {'share_server_id': share_server['id']})
            return

        different_keys = self._get_different_keys_for_equal_ss_type(
            current_security_service, new_security_service)
        if not different_keys:
            msg = _("The former and the latter security services are "
                    "equal. Nothing to do.")
            LOG.debug(msg)
            return

        if 'dns_ip' in different_keys:
            dns_ips = set()
            domains = set()
            # Read all dns-ips and domains from other security services
            for sec_svc in network_info[0]['security_services']:
                if sec_svc['type'] == current_type:
                    # skip the one that we are replacing
                    continue
                if sec_svc.get('dns_ip') is not None:
                    for dns_ip in sec_svc['dns_ip'].split(','):
                        dns_ips.add(dns_ip.strip())
                if sec_svc.get('domain') is not None:
                    domains.add(sec_svc['domain'])
            # Merge with the new dns configuration
            if new_security_service.get('dns_ip') is not None:
                for dns_ip in new_security_service['dns_ip'].split(','):
                    dns_ips.add(dns_ip.strip())
            if new_security_service.get('domain') is not None:
                domains.add(new_security_service['domain'])

            # Update vserver DNS configuration
            vserver_client.update_dns_configuration(dns_ips, domains)

        if new_type == 'kerberos':
            if 'server' in different_keys:
                # NOTE(dviroel): Only IPs will be updated here, new principals
                # won't be configured here. It is expected that only the IP was
                # changed, but the KDC remains the same.
                LOG.debug('Updating kerberos realm on NetApp backend.')
                vserver_client.update_kerberos_realm(new_security_service)

        elif new_type == 'active_directory':
            vserver_client.modify_active_directory_security_service(
                vserver_name, different_keys, new_security_service,
                current_security_service)
        else:
            vserver_client.modify_ldap(new_security_service,
                                       current_security_service)

        LOG.info("Security service configuration was updated for share server "
                 "'%(share_server_id)s'",
                 {'share_server_id': share_server['id']})

    def check_update_share_server_security_service(
            self, context, share_server, network_info,
            new_security_service, current_security_service=None):
        current_type = (
            current_security_service['type'].lower()
            if current_security_service else '')

        if not self._is_security_service_valid(new_security_service):
            self.message_api.create(
                context,
                message_field.Action.ADD_UPDATE_SECURITY_SERVICE,
                new_security_service['project_id'],
                resource_type=message_field.Resource.SECURITY_SERVICE,
                resource_id=new_security_service['id'],
                detail=(message_field.Detail
                        .UNSUPPORTED_ADD_UDPATE_SECURITY_SERVICE))
            return False

        if current_security_service:
            if current_type != 'ldap':
                # NOTE(dviroel): We don't support domain/realm updates for
                # Kerberos security service, because it might require a new SPN
                # to be created and to destroy the old one, thus disrupting all
                # shares hosted by this share server. Same issue can happen
                # with AD domain modifications.
                if (current_security_service['domain'].lower() !=
                        new_security_service['domain'].lower()):
                    msg = _("Currently the driver does not support updates "
                            "in the security service 'domain'.")
                    LOG.info(msg)
                    return False
        return True

    def check_update_share_server_network_allocations(
            self, context, share_server, current_network_allocations,
            new_share_network_subnet, security_services, share_instances,
            share_instances_rules):
        """Check if new network configuration is valid."""
        LOG.debug('Checking if network configuration is valid to update share'
                  'server %s.', share_server['id'])
        # Get segmentation_id from current allocations to check if added
        # subnet is in the same network segment as the others.
        ref_subnet = current_network_allocations['subnets'][0]
        ref_subnet_allocation = ref_subnet['network_allocations'][0]
        seg_id = ref_subnet_allocation['segmentation_id']
        new_subnet_seg_id = new_share_network_subnet['segmentation_id']
        network_info = [dict(segmentation_id=seg_id),
                        dict(segmentation_id=new_subnet_seg_id)]
        is_valid_configuration = True
        try:
            self._validate_network_type([new_share_network_subnet])
            self._validate_share_network_subnets(network_info)
        except exception.NetworkBadConfigurationException as e:
            LOG.error('Invalid share server network allocation. %s', e)
            is_valid_configuration = False

        return is_valid_configuration

    def _build_model_update(self, current_network_allocations,
                            new_network_allocations, export_locations=None):
        """Updates server details for a new set of network allocations"""
        ports = {}
        for subnet in current_network_allocations['subnets']:
            for alloc in subnet['network_allocations']:
                ports[alloc['id']] = alloc['ip_address']

        for alloc in new_network_allocations['network_allocations']:
            ports[alloc['id']] = alloc['ip_address']

        model_update = {'server_details': {'ports': jsonutils.dumps(ports)}}
        if export_locations:
            model_update.update({'share_updates': export_locations})

        return model_update

    def update_share_server_network_allocations(
            self, context, share_server, current_network_allocations,
            new_network_allocations, security_services, shares, snapshots):
        """Update network allocations for the share server."""
        vserver_name = self._get_vserver_name(share_server['id'])
        vserver_client = self._get_api_client(vserver=vserver_name)
        ipspace_name = self._client.get_vserver_ipspace(vserver_name)
        network_info = [new_network_allocations]

        LOG.debug('Adding new subnet allocations to share server %s',
                  share_server['id'])
        try:
            self._setup_network_for_vserver(
                vserver_name, vserver_client, network_info, ipspace_name,
                enable_nfs=False, security_services=None, nfs_config=None)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to update vserver network configuration.")
                updates = self._build_model_update(
                    current_network_allocations, new_network_allocations,
                    export_locations=None)
                e.detail_data = updates

        updated_export_locations = {}
        for share in shares:
            if share['replica_state'] == constants.REPLICA_STATE_ACTIVE:
                host = share['host']
                export_locations = self._create_export(
                    share, share_server, vserver_name, vserver_client,
                    clear_current_export_policy=False,
                    ensure_share_already_exists=True,
                    share_host=host)
                updated_export_locations.update(
                    {share['id']: export_locations})

        updates = self._build_model_update(
            current_network_allocations, new_network_allocations,
            updated_export_locations)
        return updates
