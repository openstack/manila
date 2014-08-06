# Copyright (c) 2014 NetApp, Inc.
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
"""
NetApp specific NAS storage driver. Supports NFS and CIFS protocols.

This driver requires ONTAP Cluster mode storage system
with installed CIFS and NFS licenses.
"""

import hashlib
import os
import re

from oslo.config import cfg

from manila import exception
from manila.openstack.common import excutils
from manila.openstack.common import log
from manila.share.drivers.netapp import api as naapi
from manila.share.drivers.netapp import driver
from manila import utils


NETAPP_NAS_OPTS = [
    cfg.StrOpt('netapp_vserver_name_template',
               default='os_%s',
               help='Name template to use for new vserver.'),
    cfg.StrOpt('netapp_lif_name_template',
               default='os_%(net_allocation_id)s',
               help='Lif name template'),
    cfg.StrOpt('netapp_aggregate_name_search_pattern',
               default='(.*)',
               help='Pattern for searching available aggregates'
                    ' for provisioning.'),
    cfg.StrOpt('netapp_root_volume_aggregate',
               help='Name of aggregate to create root volume on.'),
    cfg.StrOpt('netapp_root_volume_name',
               default='root',
               help='Root volume name.')
]


CONF = cfg.CONF
CONF.register_opts(NETAPP_NAS_OPTS)

LOG = log.getLogger(__name__)


def ensure_vserver(f):
    def wrap(self, *args, **kwargs):
        server = kwargs.get('share_server')
        if not server:
            # For now cmode driver does not support flat networking.
            raise exception.NetAppException(_('Share sever is not provided.'))
        vserver_name = server['backend_details'].get('vserver_name') if \
            server.get('backend_details') else None
        if not vserver_name:
            raise exception.NetAppException(_('Vserver name missing in '
                                              'backend details.'))
        if not self._vserver_exists(vserver_name):
            raise exception.VserverUnavailable(vserver=vserver_name)
        return f(self, *args, **kwargs)
    return wrap


class NetAppClusteredShareDriver(driver.NetAppShareDriver):
    """
    NetApp specific ONTAP C-mode driver.

    Supports NFS and CIFS protocols.
    Uses Ontap devices as backend to create shares
    and snapshots.
    Sets up vServer for each share_network.
    Connectivity between storage and client VM is organized
    by plugging vServer's network interfaces into neutron subnet
    that VM is using.
    """

    def __init__(self, db, *args, **kwargs):
        super(NetAppClusteredShareDriver, self).__init__(db, *args, **kwargs)
        if self.configuration:
            self.configuration.append_config_values(NETAPP_NAS_OPTS)
        self.api_version = (1, 15)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or "NetApp_Cluster_Mode"

    def do_setup(self, context):
        """Prepare once the driver.

        Called once by the manager after the driver is loaded.
        Sets up clients, check licenses, sets up protocol
        specific helpers.
        """
        self._client = driver.NetAppApiClient(self.api_version,
                                              configuration=self.configuration)
        self._setup_helpers()

    def check_for_setup_error(self):
        """Raises error if prerequisites are not met."""
        self._check_licenses()

    def _calculate_capacity(self):
        """Calculates capacity

        Returns tuple (total, free) in bytes.
        """
        aggrs = self._find_match_aggregates()
        aggr_space_attrs = [aggr.get_child_by_name('aggr-space-attributes')
                            for aggr in aggrs]
        total = sum([int(aggr.get_child_content('size-total'))
                     for aggr in aggr_space_attrs])
        free = max([int(aggr.get_child_content('size-available'))
                    for aggr in aggr_space_attrs])
        return total, free

    def setup_server(self, network_info, metadata=None):
        """Creates and configures new vserver."""
        LOG.debug('Creating server %s' % network_info['server_id'])
        vserver_name = self._vserver_create_if_not_exists(network_info)
        return {'vserver_name': vserver_name}

    def _get_cluster_nodes(self):
        """Get all available cluster nodes."""
        response = self._client.send_request('system-node-get-iter')
        nodes_info_list = response.get_child_by_name('attributes-list')\
            .get_children() if response.get_child_by_name('attributes-list') \
            else []
        nodes = [node_info.get_child_content('node') for node_info
                 in nodes_info_list]
        return nodes

    def _get_node_data_port(self, node):
        """Get data port on the node."""
        args = {'query': {'net-port-info': {'node': node,
                          'port-type': 'physical',
                          'role': 'data'}}}
        port_info = self._client.send_request('net-port-get-iter', args)
        try:
            port = port_info.get_child_by_name('attributes-list')\
                .get_child_by_name('net-port-info')\
                .get_child_content('port')
        except AttributeError:
            msg = _("Data port does not exists for node %s") % node
            LOG.error(msg)
            raise exception.NetAppException(msg)
        return port

    def _create_vserver(self, vserver_name):
        """Creates new vserver and assigns aggregates."""
        create_args = {'vserver-name': vserver_name,
                       'root-volume-security-style': 'unix',
                       'root-volume-aggregate':
                           self.configuration.netapp_root_volume_aggregate,
                       'root-volume':
                           self.configuration.netapp_root_volume_name,
                       'name-server-switch': {'nsswitch': 'file'}}
        self._client.send_request('vserver-create', create_args)
        aggrs = self._find_match_aggregates()
        aggr_list = [{'aggr-name': aggr.get_child_content('aggregate-name')}
                     for aggr in aggrs]
        modify_args = {'aggr-list': aggr_list,
                       'vserver-name': vserver_name}
        self._client.send_request('vserver-modify', modify_args)

    def _find_match_aggregates(self):
        """Find all aggregates match pattern."""
        pattern = self.configuration.netapp_aggregate_name_search_pattern
        try:
            aggrs = self._client.send_request('aggr-get-iter')\
                .get_child_by_name('attributes-list').get_children()
        except AttributeError:
            msg = _("Have not found aggregates match pattern %s")\
                  % pattern
            LOG.error(msg)
            raise exception.NetAppException(msg)
        aggr_list = [aggr for aggr in aggrs if re.match(
            pattern, aggr.get_child_content('aggregate-name'))]
        return aggr_list

    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        return int(self._client.send_request(
            'system-node-get-iter').get_child_content('num-records'))

    def _create_net_iface(self, ip, netmask, vlan, node, port, vserver_name,
                          allocation_id):
        """Creates lif on vlan port."""
        vlan_iface_name = "%(port)s-%(tag)s" % {'port': port, 'tag': vlan}
        try:
            args = {
                'vlan-info': {
                    'parent-interface': port,
                    'node': node,
                    'vlanid': vlan
                }
            }
            self._client.send_request('net-vlan-create', args)
        except naapi.NaApiError as e:
            if e.code == '13130':
                LOG.debug("Vlan %(vlan)s already exists on port %(port)s" %
                          {'vlan': vlan, 'port': port})
            else:
                raise exception.NetAppException(
                    _("Failed to create vlan %(vlan)s on "
                      "port %(port)s. %(err_msg)") %
                    {'vlan': vlan, 'port': port, 'err_msg': e.message})
        iface_name = self.configuration.netapp_lif_name_template % \
                     {'node': node, 'net_allocation_id': allocation_id}
        LOG.debug('Creating LIF %(lif)r for vserver %(vserver)s '
                        % {'lif': iface_name, 'vserver': vserver_name})
        args = {'address': ip,
                'administrative-status': 'up',
                'data-protocols': [
                    {'data-protocol': 'nfs'},
                    {'data-protocol': 'cifs'}
                ],
                'home-node': node,
                'home-port': vlan_iface_name,
                'netmask': netmask,
                'interface-name': iface_name,
                'role': 'data',
                'vserver': vserver_name,
                }
        self._client.send_request('net-interface-create', args)

    def _delete_net_iface(self, iface_name):
        """Deletes lif."""
        args = {'vserver': None,
                'interface-name': iface_name}
        self._client.send_request('net-interface-delete', args)

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {'CIFS': NetAppClusteredCIFSHelper(),
                         'NFS': NetAppClusteredNFSHelper()}

    def _vserver_exists(self, vserver_name):
        args = {'query': {'vserver-info': {'vserver-name': vserver_name}}}

        LOG.debug('Checking if vserver exists')
        vserver_info = self._client.send_request('vserver-get-iter', args)
        if int(vserver_info.get_child_content('num-records')):
            return True
        else:
            return False

    def _vserver_create_if_not_exists(self, network_info):
        """Creates vserver if not exists with given parameters."""
        vserver_name = self.configuration.netapp_vserver_name_template % \
                       network_info['server_id']
        vserver_client = driver.NetAppApiClient(
            self.api_version, vserver=vserver_name,
            configuration=self.configuration)
        if not self._vserver_exists(vserver_name):
            LOG.debug('Vserver %s does not exist, creating' % vserver_name)
            self._create_vserver(vserver_name)
        nodes = self._get_cluster_nodes()

        node_network_info = zip(nodes, network_info['network_allocations'])
        netmask = utils.cidr_to_netmask(network_info['cidr'])
        try:
            for node, net_info in node_network_info:
                port = self._get_node_data_port(node)
                ip = net_info['ip_address']
                self._create_lif_if_not_exists(
                    vserver_name, net_info['id'],
                    network_info['segmentation_id'], node, port,
                    ip, netmask, vserver_client)
        except naapi.NaApiError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("Failed to create network interface"))
                self._delete_vserver(vserver_name, vserver_client)

        self._enable_nfs(vserver_client)

        security_services = network_info.get('security_services')
        if security_services:
            self._setup_security_services(security_services, vserver_client,
                                          vserver_name)
        return vserver_name

    def _setup_security_services(self, security_services, vserver_client,
                                 vserver_name):
        modify_args = {
            'name-mapping-switch': {
                'nmswitch': 'ldap,file'},
            'name-server-switch': {
                'nsswitch': 'ldap,file'},
            'vserver-name': vserver_name}
        self._client.send_request('vserver-modify', modify_args)
        for security_service in security_services:
            if security_service['type'].lower() == "ldap":
                self._configure_ldap(security_service, vserver_client)
            elif security_service['type'].lower() == "active_directory":
                self._configure_active_directory(security_service,
                                                 vserver_client)
            elif security_service['type'].lower() == "kerberos":
                self._configure_kerberos(vserver_name, security_service,
                                         vserver_client)
            else:
                raise exception.NetAppException(
                    _('Unsupported protocol %s for NetApp driver')
                    % security_service['type'])

    def _enable_nfs(self, vserver_client):
        """Enables NFS on vserver."""
        vserver_client.send_request('nfs-enable')
        args = {'is-nfsv40-enabled': 'true'}
        vserver_client.send_request('nfs-service-modify', args)
        args = {
            'client-match': '0.0.0.0/0',
            'policy-name': 'default',
            'ro-rule': {
                'security-flavor': 'any'
            },
            'rw-rule': {
                'security-flavor': 'any'
            }
        }
        vserver_client.send_request('export-rule-create', args)

    def _configure_ldap(self, data, vserver_client):
        """Configures LDAP on vserver."""
        config_name = hashlib.md5(data['id']).hexdigest()
        args = {'ldap-client-config': config_name,
                'servers': {
                    'ip-address': data['server']
                },
                'tcp-port': '389',
                'schema': 'RFC-2307',
                'bind-password': data['password']}
        vserver_client.send_request('ldap-client-create', args)
        args = {'client-config': config_name,
                'client-enabled': 'true'}
        vserver_client.send_request('ldap-config-create', args)

    def _configure_dns(self, data, vserver_client):
        args = {
            'domains': {
            'string': data['domain']
            },
            'name-servers': {
                'ip-address': data['dns_ip']
            },
            'dns-state': 'enabled'
        }
        try:
            vserver_client.send_request('net-dns-create', args)
        except naapi.NaApiError as e:
            if e.code == '13130':
                LOG.error(_("Dns exists for vserver"))
            else:
                raise exception.NetAppException(
                    _("Failed to configure DNS. %s") % e.message)

    def _configure_kerberos(self, vserver, data, vserver_client):
        """Configures Kerberos for NFS on vServer."""
        args = {'admin-server-ip': data['server'],
                'admin-server-port': '749',
                'clock-skew': '5',
                'comment': '',
                'config-name': data['id'],
                'kdc-ip': data['server'],
                'kdc-port': '88',
                'kdc-vendor': 'other',
                'password-server-ip': data['server'],
                'password-server-port': '464',
                'realm': data['domain'].upper()}
        try:
            self._client.send_request('kerberos-realm-create', args)
        except naapi.NaApiError as e:
            if e.code == '13130':
                LOG.debug("Kerberos realm config already exists")
            else:
                raise exception.NetAppException(
                    _("Failed to configure Kerberos. %s") % e.message)

        self._configure_dns(data, vserver_client)
        spn = 'nfs/' + vserver.replace('_', '-') + '.' + data['domain'] + '@'\
              + data['domain'].upper()
        lifs = self._get_lifs(vserver_client)
        if not lifs:
            msg = _("Cannot set up kerberos. There are no lifs configured")
            LOG.error(msg)
            raise Exception(msg)
        for lif_name in lifs:
            args = {
                'admin-password': data['password'],
                'admin-user-name': data['user'],
                'interface-name': lif_name,
                'is-kerberos-enabled': 'true',
                'service-principal-name': spn
            }
        vserver_client.send_request('kerberos-config-modify', args)

    def _configure_active_directory(self, data, vserver_client):
        """Configures AD on vserver."""
        self._configure_dns(data, vserver_client)
        args = {
            'admin-username': data['user'],
            'admin-password': data['password'],
            'force-account-overwrite': 'true',
            'cifs-server': data['server'],
            'domain': data['domain'],
        }
        try:
            vserver_client.send_request('cifs-server-create', args)
        except naapi.NaApiError as e:
            if e.code == '13001':
                LOG.debug("CIFS server entry already exists")
            else:
                raise exception.NetAppException(
                    _("Failed to create CIFS server entry. %s") % e.message)

    def _get_lifs(self, vserver_client):
        lifs_info = vserver_client.send_request('net-interface-get-iter')
        try:
            lif_names = [lif.get_child_content('interface-name') for lif in
                         lifs_info.get_child_by_name('attributes-list')
                         .get_children()]
        except AttributeError:
            lif_names = []
        return lif_names

    def _create_lif_if_not_exists(self, vserver_name, allocation_id, vlan,
                                  node, port, ip, netmask, vserver_client):
        """Creates lif for vserver."""
        args = {
            'query': {
                'net-interface-info': {
                    'address': ip,
                    'home-node': node,
                    'home-port': port,
                    'netmask': netmask,
                    'vserver': vserver_name}
            }
        }
        ifaces = vserver_client.send_request('net-interface-get-iter',
                                                   args)
        if not ifaces.get_child_content('num_records') or \
                        ifaces.get_child_content('num_records') == '0':
            self._create_net_iface(ip, netmask, vlan, node, port, vserver_name,
                                   allocation_id)

    def get_available_aggregates_for_vserver(self, vserver, vserver_client):
        """Returns aggregate list for the vserver."""
        LOG.debug('Finding available aggreagates for vserver %s' % vserver)
        response = vserver_client.send_request('vserver-get')
        vserver_info = response.get_child_by_name('attributes')\
            .get_child_by_name('vserver-info')
        aggr_list_elements = vserver_info\
            .get_child_by_name('vserver-aggr-info-list').get_children()

        if not aggr_list_elements:
            msg = _("No aggregate assigned to vserver %s")
            raise exception.NetAppException(msg % vserver)

        # return dict of key-value pair of aggr_name:si$
        aggr_dict = {}

        for aggr_elem in aggr_list_elements:
            aggr_name = aggr_elem.get_child_content('aggr-name')
            aggr_size = int(aggr_elem.get_child_content('aggr-availsize'))
            aggr_dict[aggr_name] = aggr_size
        LOG.debug("Found available aggregates: %r" % aggr_dict)
        return aggr_dict

    @ensure_vserver
    def create_share(self, context, share, share_server=None):
        """Creates new share."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = driver.NetAppApiClient(
            self.api_version, vserver=vserver,
            configuration=self.configuration)
        self._allocate_container(share, vserver, vserver_client)
        return self._create_export(share, vserver, vserver_client)

    @ensure_vserver
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Creates new share form snapshot."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = driver.NetAppApiClient(
            self.api_version, vserver=vserver,
            configuration=self.configuration)

        self._allocate_container_from_snapshot(share, snapshot, vserver,
                                               vserver_client)
        return self._create_export(share, vserver, vserver_client)

    def _allocate_container(self, share, vserver, vserver_client):
        """Create new share on aggregate."""
        share_name = self._get_valid_share_name(share['id'])
        aggregates = self.get_available_aggregates_for_vserver(vserver,
                                                               vserver_client)
        aggregate = max(aggregates, key=lambda m: aggregates[m])

        LOG.debug('Creating volume %(share_name)s on '
                  'aggregate %(aggregate)s'
                  % {'share_name': share_name, 'aggregate': aggregate})
        args = {'containing-aggr-name': aggregate,
                'size': str(share['size']) + 'g',
                'volume': share_name,
                'junction-path': '/%s' % share_name
                }
        vserver_client.send_request('volume-create', args)

    def _allocate_container_from_snapshot(self, share, snapshot, vserver,
                                          vserver_client):
        """Clones existing share."""
        share_name = self._get_valid_share_name(share['id'])
        parent_share_name = self._get_valid_share_name(snapshot['share_id'])
        parent_snapshot_name = self._get_valid_snapshot_name(snapshot['id'])

        LOG.debug('Creating volume from snapshot %s' % snapshot['id'])
        args = {'volume': share_name,
                'parent-volume': parent_share_name,
                'parent-snapshot': parent_snapshot_name,
                'junction-path': '/%s' % share_name
                }

        vserver_client.send_request('volume-clone-create', args)

    def _share_exists(self, share_name, vserver_client):
        args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': share_name
                    }
                }
            }
        }
        response = vserver_client.send_request('volume-get-iter', args)
        if int(response.get_child_content('num-records')):
            return True

    def _deallocate_container(self, share, vserver_client):
        """Free share space."""
        self._share_unmount(share, vserver_client)
        self._offline_share(share, vserver_client)
        self._delete_share(share, vserver_client)

    def _offline_share(self, share, vserver_client):
        """Sends share offline. Required before deleting a share."""
        share_name = self._get_valid_share_name(share['id'])
        args = {'name': share_name}
        LOG.debug('Offline volume %s' % share_name)
        vserver_client.send_request('volume-offline', args)

    def _delete_share(self, share, vserver_client):
        """Destroys share on a target OnTap device."""
        share_name = self._get_valid_share_name(share['id'])
        args = {'name': share_name}
        LOG.debug('Deleting share %s' % share_name)
        vserver_client.send_request('volume-destroy', args)

    @ensure_vserver
    def delete_share(self, context, share, share_server=None):
        """Deletes share."""
        share_name = self._get_valid_share_name(share['id'])
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = driver.NetAppApiClient(
            self.api_version, vserver=vserver,
            configuration=self.configuration)
        if self._share_exists(share_name, vserver_client):
            self._remove_export(share, vserver_client)
            self._deallocate_container(share, vserver_client)
        else:
            LOG.info(_("Share %s does not exists") % share['id'])

    def _create_export(self, share, vserver, vserver_client):
        """Creates NAS storage."""
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        share_name = self._get_valid_share_name(share['id'])
        args = {
            'query': {
                'net-interface-info': {'vserver': vserver}
            }
        }
        ifaces = vserver_client.send_request('net-interface-get-iter', args)
        if not int(ifaces.get_child_content('num-records')):
            raise exception.NetAppException(
                _("Cannot find network interfaces for vserver %s.") % vserver)
        ifaces_list = ifaces.get_child_by_name('attributes-list')\
            .get_children()
        ip_address = ifaces_list[0].get_child_content('address')
        export_location = helper.create_share(share_name, ip_address)
        return export_location

    @ensure_vserver
    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of a share."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = driver.NetAppApiClient(
            self.api_version, vserver=vserver,
            configuration=self.configuration)
        share_name = self._get_valid_share_name(snapshot['share_id'])
        snapshot_name = self._get_valid_snapshot_name(snapshot['id'])
        args = {'volume': share_name,
                'snapshot': snapshot_name}
        LOG.debug('Creating snapshot %s' % snapshot_name)
        vserver_client.send_request('snapshot-create', args)

    def _remove_export(self, share, vserver_client):
        """Deletes NAS storage."""
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        target = helper.get_target(share)
        # share may be in error state, so there's no share and target
        if target:
            helper.delete_share(share)

    @ensure_vserver
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot of a share."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = driver.NetAppApiClient(
            self.api_version, vserver=vserver,
            configuration=self.configuration)
        share_name = self._get_valid_share_name(snapshot['share_id'])
        snapshot_name = self._get_valid_snapshot_name(snapshot['id'])

        self._is_snapshot_busy(share_name, snapshot_name, vserver_client)
        args = {'snapshot': snapshot_name,
                'volume': share_name}
        LOG.debug('Deleting snapshot %s' % snapshot_name)
        vserver_client.send_request('snapshot-delete', args)

    def _is_snapshot_busy(self, share_name, snapshot_name, vserver_client):
        """Raises ShareSnapshotIsBusy if snapshot is busy."""
        args = {'volume': share_name}
        snapshots = vserver_client.send_request('snapshot-list-info',
                                                      args)
        for snap in snapshots.get_child_by_name('snapshots')\
            .get_children():
            if snap.get_child_by_name('name').get_content() == snapshot_name\
                and snap.get_child_by_name('busy').get_content() == 'true':
                return True

    def _share_unmount(self, share, vserver_client):
        """Unmounts share (required before deleting)."""
        share_name = self._get_valid_share_name(share['id'])
        args = {'volume-name': share_name}
        LOG.debug('Unmounting volume %s' % share_name)
        vserver_client.send_request('volume-unmount', args)

    @ensure_vserver
    def allow_access(self, context, share, access, share_server=None):
        """Allows access to a given NAS storage for IPs in access."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = driver.NetAppApiClient(
            self.api_version, vserver=vserver,
            configuration=self.configuration)
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        return helper.allow_access(context, share, access)

    @ensure_vserver
    def deny_access(self, context, share, access, share_server=None):
        """Denies access to a given NAS storage for IPs in access."""
        vserver = share_server['backend_details']['vserver_name']
        vserver_client = driver.NetAppApiClient(
            self.api_version, vserver=vserver,
            configuration=self.configuration)
        helper = self._get_helper(share)
        helper.set_client(vserver_client)
        return helper.deny_access(context, share, access)

    def _delete_vserver(self, vserver_name, vserver_client,
                        security_services=None):
        """
        Delete vserver.

        Checks if vserver exists and does not have active shares.
        Offlines and destroys root volumes.
        Deletes vserver.
        """
        if not self._vserver_exists(vserver_name):
            LOG.error(_("Vserver %s does not exists.") % vserver_name)
            return
        volumes_data = vserver_client.send_request('volume-get-iter')
        volumes_count = int(volumes_data.get_child_content('num-records'))
        if volumes_count == 1:
            try:
                vserver_client.send_request(
                    'volume-offline',
                    {'name': self.configuration.netapp_root_volume_name})
            except naapi.NaApiError as e:
                if e.code == '13042':
                    LOG.error(_("Volume %s is already offline.")
                              % self.configuration.netapp_root_volume_name)
                else:
                    raise e
            vserver_client.send_request(
                'volume-destroy',
                {'name': self.configuration.netapp_root_volume_name})
        elif volumes_count > 1:
            msg = _("Error deleting vserver. "
                    "Vserver %s has shares.") % vserver_name
            LOG.error(msg)
            raise exception.NetAppException(msg)
        if security_services:
            for service in security_services:
                if service['type'] == 'active_directory':
                    args = {
                        'admin-password': service['password'],
                        'admin-username': service['user'],
                    }
                    try:
                        vserver_client.send_request('cifs-server-delete',
                                                    args)
                    except naapi.NaApiError as e:
                        if e.code == "15661":
                            LOG.error(_("Cifs server does not exists for"
                                      " vserver %s") % vserver_name)
                        else:
                            vserver_client.send_request('cifs-server-delete')
        self._client.send_request('vserver-destroy',
                                  {'vserver-name': vserver_name})

    def teardown_server(self, server_details, security_services=None):
        """Teardown share network."""
        vserver_name = server_details['vserver_name']
        vserver_client = driver.NetAppApiClient(
            self.api_version, vserver=vserver_name,
            configuration=self.configuration)
        self._delete_vserver(vserver_name, vserver_client,
                             security_services=security_services)


class NetAppClusteredNFSHelper(driver.NetAppNFSHelper):
    """Netapp specific cluster-mode NFS sharing driver."""
    def create_share(self, share_name, export_ip):
        """Creates NFS share."""
        export_pathname = os.path.join('/', share_name)
        self.add_rules(export_pathname, ['localhost'])
        export_location = ':'.join([export_ip, export_pathname])
        return export_location

    def allow_access_by_user(self, share, user):
        user, _x, group = user.partition(':')
        args = {
            'attributes': {
                'volume-attributes': {
                    'volume-security-attributes': {
                        'volume-security-unix-attributes': {
                            'user-id': user,
                            'group-id': group or 'root'
                        }
                    }
                }
            },
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'junction-path': self._get_export_path(share)
                    }
                }
            }
        }
        self._client.send_request('volume-modify-iter', args)

    def deny_access_by_user(self, share, user):
        args = {
            'attributes': {
                'volume-security-attributes': {
                    'volume-security-unix-attributes': {
                        'user': 'root'
                    }
                }
            },
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'junction-path': self._get_export_path(share)
                    }
                }
            }
        }
        self._client.send_request('volume-modify-iter', args)


class NetAppClusteredCIFSHelper(driver.NetAppCIFSHelper):
    """Netapp specific cluster-mode CIFS sharing driver."""

    def create_share(self, share_name, export_ip):

        self._add_share(share_name)

        cifs_location = self._set_export_location(export_ip, share_name)
        self._restrict_access('Everyone', share_name)

        return cifs_location

    def _add_share(self, share_name):
        """Creates CIFS share on target OnTap host."""
        share_path = '/%s' % share_name
        args = {'path': share_path,
                'share-name': share_name}
        self._client.send_request('cifs-share-create', args)

    def delete_share(self, share):
        """Deletes CIFS storage."""
        host_ip, share_name = self._get_export_location(share)
        args = {'share-name': share_name}
        self._client.send_request('cifs-share-delete', args)

    def _allow_access_for(self, username, share_name):
        """Allows access to the CIFS share for a given user."""
        args = {'permission': 'full_control',
                'share': share_name,
                'user-or-group': username}
        self._client.send_request('cifs-share-access-control-create', args)

    def _restrict_access(self, user_name, share_name):
        args = {'user-or-group': user_name,
                'share': share_name}
        self._client.send_request('cifs-share-access-control-delete', args)
