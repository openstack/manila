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
from oslo_utils import excutils

from manila import exception
from manila.i18n import _, _LE, _LW
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_base
from manila.share.drivers.netapp import utils as na_utils
from manila import utils


LOG = log.getLogger(__name__)
SUPPORTED_NETWORK_TYPES = (None, 'flat', 'vlan')
SEGMENTED_NETWORK_TYPES = ('vlan',)


class NetAppCmodeMultiSVMFileStorageLibrary(
        lib_base.NetAppCmodeFileStorageLibrary):

    @na_utils.trace
    def check_for_setup_error(self):

        if self._have_cluster_creds:
            if self.configuration.netapp_vserver:
                msg = _LW('Vserver is specified in the configuration. This is '
                          'ignored when the driver is managing share servers.')
                LOG.warning(msg)

        else:  # only have vserver creds, which is an error in multi_svm mode
            msg = _('Cluster credentials must be specified in the '
                    'configuration when the driver is managing share servers.')
            raise exception.InvalidInput(reason=msg)

        # Ensure one or more aggregates are available.
        if not self._find_matching_aggregates():
            msg = _('No aggregates are available for provisioning shares. '
                    'Ensure that the configuration option '
                    'netapp_aggregate_name_search_pattern is set correctly.')
            raise exception.NetAppException(msg)

        super(NetAppCmodeMultiSVMFileStorageLibrary, self).\
            check_for_setup_error()

    @na_utils.trace
    def _get_vserver(self, share_server=None):

        if not share_server:
            msg = _('Share server not provided')
            raise exception.InvalidInput(reason=msg)

        backend_details = share_server.get('backend_details')
        vserver = backend_details.get(
            'vserver_name') if backend_details else None

        if not vserver:
            msg = _('Vserver name is absent in backend details. Please '
                    'check whether Vserver was created properly.')
            raise exception.VserverNotSpecified(msg)

        if not self._client.vserver_exists(vserver):
            raise exception.VserverNotFound(vserver=vserver)

        vserver_client = self._get_api_client(vserver)
        return vserver, vserver_client

    @na_utils.trace
    def _handle_housekeeping_tasks(self):
        """Handle various cleanup activities."""
        self._client.prune_deleted_nfs_export_policies()

        super(NetAppCmodeMultiSVMFileStorageLibrary, self).\
            _handle_housekeeping_tasks()

    @na_utils.trace
    def _find_matching_aggregates(self):
        """Find all aggregates match pattern."""
        aggregate_names = self._client.list_aggregates()
        pattern = self.configuration.netapp_aggregate_name_search_pattern
        return [aggr_name for aggr_name in aggregate_names
                if re.match(pattern, aggr_name)]

    @na_utils.trace
    def setup_server(self, network_info, metadata=None):
        """Creates and configures new Vserver."""
        LOG.debug('Creating server %s', network_info['server_id'])
        self._validate_network_type(network_info)

        vserver_name = self._get_vserver_name(network_info['server_id'])
        server_details = {'vserver_name': vserver_name}

        try:
            self._create_vserver(vserver_name, network_info)
        except Exception as e:
            e.detail_data = {'server_details': server_details}
            raise

        return server_details

    @na_utils.trace
    def _validate_network_type(self, network_info):
        """Raises exception if the segmentation type is incorrect."""
        if network_info['network_type'] not in SUPPORTED_NETWORK_TYPES:
            msg = _('The specified network type %s is unsupported by the '
                    'NetApp clustered Data ONTAP driver')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network_info['network_type'])

    @na_utils.trace
    def _get_vserver_name(self, server_id):
        return self.configuration.netapp_vserver_name_template % server_id

    @na_utils.trace
    def _create_vserver(self, vserver_name, network_info):
        """Creates Vserver with given parameters if it doesn't exist."""

        if self._client.vserver_exists(vserver_name):
            msg = _('Vserver %s already exists.')
            raise exception.NetAppException(msg % vserver_name)

        ipspace_name = self._create_ipspace(network_info)

        LOG.debug('Vserver %s does not exist, creating.', vserver_name)
        self._client.create_vserver(
            vserver_name,
            self.configuration.netapp_root_volume_aggregate,
            self.configuration.netapp_root_volume,
            self._find_matching_aggregates(),
            ipspace_name)

        vserver_client = self._get_api_client(vserver=vserver_name)
        security_services = None
        try:
            self._create_vserver_lifs(vserver_name,
                                      vserver_client,
                                      network_info,
                                      ipspace_name)

            vserver_client.enable_nfs()

            security_services = network_info.get('security_services')
            if security_services:
                self._client.setup_security_services(security_services,
                                                     vserver_client,
                                                     vserver_name)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to configure Vserver."))
                self._delete_vserver(vserver_name,
                                     security_services=security_services)

    def _get_valid_ipspace_name(self, network_id):
        """Get IPspace name according to network id."""
        return 'ipspace_' + network_id.replace('-', '_')

    @na_utils.trace
    def _create_ipspace(self, network_info):
        """If supported, create an IPspace for a new Vserver."""

        if not self._client.features.IPSPACES:
            return None

        if network_info['network_type'] not in SEGMENTED_NETWORK_TYPES:
            return client_cmode.DEFAULT_IPSPACE

        # NOTE(cknight): Neutron needs cDOT IP spaces because it can provide
        # overlapping IP address ranges for different subnets.  That is not
        # believed to be an issue for any of Manila's other network plugins.
        ipspace_id = network_info.get('neutron_subnet_id')
        if not ipspace_id:
            return client_cmode.DEFAULT_IPSPACE

        ipspace_name = self._get_valid_ipspace_name(ipspace_id)
        if not self._client.ipspace_exists(ipspace_name):
            self._client.create_ipspace(ipspace_name)

        return ipspace_name

    @na_utils.trace
    def _create_vserver_lifs(self, vserver_name, vserver_client,
                             network_info, ipspace_name):

        nodes = self._client.list_cluster_nodes()
        node_network_info = zip(nodes, network_info['network_allocations'])
        netmask = utils.cidr_to_netmask(network_info['cidr'])

        for node, net_info in node_network_info:
            net_id = net_info['id']
            port = self._get_node_data_port(node)
            ip = net_info['ip_address']
            self._create_lif_if_nonexistent(vserver_name,
                                            net_id,
                                            network_info['segmentation_id'],
                                            node,
                                            port,
                                            ip,
                                            netmask,
                                            ipspace_name,
                                            vserver_client)

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

    @na_utils.trace
    def _create_lif_if_nonexistent(self, vserver_name, allocation_id, vlan,
                                   node, port, ip, netmask, ipspace_name,
                                   vserver_client):
        """Creates LIF for Vserver."""
        if not vserver_client.network_interface_exists(vserver_name, node,
                                                       port, ip, netmask,
                                                       vlan):
            self._client.create_network_interface(
                ip, netmask, vlan, node, port, vserver_name, allocation_id,
                self.configuration.netapp_lif_name_template, ipspace_name)

    @na_utils.trace
    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        return len(self._client.list_cluster_nodes())

    @na_utils.trace
    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        vserver = server_details.get(
            'vserver_name') if server_details else None

        if not vserver:
            LOG.warning(_LW("Vserver not specified for share server being "
                            "deleted. Deletion of share server record will "
                            "proceed anyway."))
            return

        elif not self._client.vserver_exists(vserver):
            LOG.warning(_LW("Could not find Vserver for share server being "
                            "deleted: %s. Deletion of share server "
                            "record will proceed anyway."), vserver)
            return

        self._delete_vserver(vserver, security_services=security_services)

    @na_utils.trace
    def _delete_vserver(self, vserver, security_services=None):
        """Delete a Vserver plus IPspace and security services as needed."""

        ipspace_name = self._client.get_vserver_ipspace(vserver)

        vserver_client = self._get_api_client(vserver=vserver)
        self._client.delete_vserver(vserver,
                                    vserver_client,
                                    security_services=security_services)

        if ipspace_name and not self._client.ipspace_has_data_vservers(
                ipspace_name):
            self._client.delete_ipspace(ipspace_name)
