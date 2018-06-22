# Copyright (c) 2016 EMC Corporation.
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
"""Unity backend for the EMC Manila driver."""
import random

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import netutils

storops = importutils.try_import('storops')
if storops:
    from storops import exception as storops_ex
    from storops.unity import enums

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.common.enas import utils as enas_utils
from manila.share.drivers.dell_emc.plugins import base as driver
from manila.share.drivers.dell_emc.plugins.unity import client
from manila.share.drivers.dell_emc.plugins.unity import utils as unity_utils
from manila.share import utils as share_utils
from manila import utils

VERSION = "4.0.0"

LOG = log.getLogger(__name__)
SUPPORTED_NETWORK_TYPES = (None, 'flat', 'vlan')

UNITY_OPTS = [
    cfg.StrOpt('unity_server_meta_pool',
               required=True,
               deprecated_name='emc_nas_server_pool',
               help='Pool to persist the meta-data of NAS server.'),
    cfg.ListOpt('unity_share_data_pools',
                deprecated_name='emc_nas_pool_names',
                help='Comma separated list of pools that can be used to '
                     'persist share data.'),
    cfg.ListOpt('unity_ethernet_ports',
                deprecated_name='emc_interface_ports',
                help='Comma separated list of ports that can be used for '
                     'share server interfaces. Members of the list '
                     'can be Unix-style glob expressions.'),
    cfg.StrOpt('emc_nas_server_container',
               deprecated_for_removal=True,
               deprecated_reason='Unity driver supports nas server auto load '
                                 'balance.',
               help='Storage processor to host the NAS server. Obsolete.'),
]

CONF = cfg.CONF
CONF.register_opts(UNITY_OPTS)


@enas_utils.decorate_all_methods(enas_utils.log_enter_exit,
                                 debug_only=True)
class UnityStorageConnection(driver.StorageConnection):
    """Implements Unity specific functionality for EMC Manila driver."""

    IP_ALLOCATIONS = 1

    @enas_utils.log_enter_exit
    def __init__(self, *args, **kwargs):
        super(UnityStorageConnection, self).__init__(*args, **kwargs)
        if 'configuration' in kwargs:
            kwargs['configuration'].append_config_values(UNITY_OPTS)

        self.client = None
        self.pool_set = None
        self.nas_server_pool = None
        self.reserved_percentage = None
        self.max_over_subscription_ratio = None
        self.port_ids_conf = None
        self.ipv6_implemented = True

        # props from super class.
        self.driver_handles_share_servers = True

    def connect(self, emc_share_driver, context):
        """Connect to Unity storage."""
        config = emc_share_driver.configuration
        storage_ip = config.emc_nas_server
        username = config.emc_nas_login
        password = config.emc_nas_password
        self.client = client.UnityClient(storage_ip, username, password)

        pool_conf = config.safe_get('unity_share_data_pools')
        self.pool_set = self._get_managed_pools(pool_conf)

        self.reserved_percentage = config.safe_get(
            'reserved_share_percentage')
        if self.reserved_percentage is None:
            self.reserved_percentage = 0

        self.max_over_subscription_ratio = config.safe_get(
            'max_over_subscription_ratio')
        self.port_ids_conf = config.safe_get('unity_ethernet_ports')
        self.validate_port_configuration(self.port_ids_conf)
        pool_name = config.unity_server_meta_pool
        self._config_pool(pool_name)

    def validate_port_configuration(self, port_ids_conf):
        """Initializes the SP and ports based on the port option."""

        ports = self.client.get_file_ports()

        sp_ports_map, unmanaged_port_ids = unity_utils.match_ports(
            ports, port_ids_conf)

        if not sp_ports_map:
            msg = (_("All the specified storage ports to be managed "
                     "do not exist. Please check your configuration "
                     "unity_ethernet_ports in manila.conf. "
                     "The available ports in the backend are %s.") %
                   ",".join([port.get_id() for port in ports]))
            raise exception.BadConfigurationException(reason=msg)

        if unmanaged_port_ids:
            LOG.info("The following specified ports are not managed by "
                     "the backend: %(unmanaged)s. This host will only "
                     "manage the storage ports: %(exist)s",
                     {'unmanaged': ",".join(unmanaged_port_ids),
                      'exist': ",".join(map(",".join,
                                            sp_ports_map.values()))})
        else:
            LOG.debug("Ports: %s will be managed.",
                      ",".join(map(",".join, sp_ports_map.values())))

        if len(sp_ports_map) == 1:
            LOG.info("Only ports of %s are configured. Configure ports "
                     "of both SPA and SPB to use both of the SPs.",
                     list(sp_ports_map)[0])

        return sp_ports_map

    def check_for_setup_error(self):
        """Check for setup error."""

    def create_share(self, context, share, share_server=None):
        """Create a share and export it based on protocol used."""
        share_name = share['id']
        size = share['size']

        # Check share's protocol.
        # Throw an exception immediately if it is an invalid protocol.
        share_proto = share['share_proto'].upper()
        proto_enum = self._get_proto_enum(share_proto)

        # Get pool name from share host field
        pool_name = self._get_pool_name_from_host(share['host'])
        # Get share server name from share server
        server_name = self._get_server_name(share_server)

        pool = self.client.get_pool(pool_name)
        try:
            nas_server = self.client.get_nas_server(server_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_("Failed to get NAS server %(server)s when "
                         "creating the share %(share)s.") %
                       {'server': server_name, 'share': share_name})
            LOG.exception(message)
            raise exception.EMCUnityError(err=message)

        locations = None
        if share_proto == 'CIFS':
            filesystem = self.client.create_filesystem(
                pool, nas_server, share_name,
                size, proto=proto_enum)
            self.client.create_cifs_share(filesystem, share_name)

            locations = self._get_cifs_location(
                nas_server.file_interface, share_name)
        elif share_proto == 'NFS':
            self.client.create_nfs_filesystem_and_share(
                pool, nas_server, share_name, size)

            locations = self._get_nfs_location(
                nas_server.file_interface, share_name)

        return locations

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Create a share from a snapshot - clone a snapshot."""
        share_name = share['id']

        # Check share's protocol.
        # Throw an exception immediately if it is an invalid protocol.
        share_proto = share['share_proto'].upper()
        self._validate_share_protocol(share_proto)

        # Get share server name from share server
        server_name = self._get_server_name(share_server)

        try:
            nas_server = self.client.get_nas_server(server_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_("Failed to get NAS server %(server)s when "
                         "creating the share %(share)s.") %
                       {'server': server_name, 'share': share_name})
            LOG.exception(message)
            raise exception.EMCUnityError(err=message)

        backend_snap = self.client.create_snap_of_snap(snapshot['id'],
                                                       share_name)

        locations = None
        if share_proto == 'CIFS':
            self.client.create_cifs_share(backend_snap, share_name)

            locations = self._get_cifs_location(
                nas_server.file_interface, share_name)
        elif share_proto == 'NFS':
            self.client.create_nfs_share(backend_snap, share_name)

            locations = self._get_nfs_location(
                nas_server.file_interface, share_name)

        return locations

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        share_name = share['id']
        try:
            backend_share = self.client.get_share(share_name,
                                                  share['share_proto'])
        except storops_ex.UnityResourceNotFoundError:
            LOG.warning("Share %s is not found when deleting the share",
                        share_name)
            return

        # Share created by the API create_share_from_snapshot()
        if self._is_share_from_snapshot(backend_share):
            filesystem = backend_share.snap.filesystem
            self.client.delete_snapshot(backend_share.snap)
        else:
            filesystem = backend_share.filesystem
            self.client.delete_share(backend_share)

        if self._is_isolated_filesystem(filesystem):
            self.client.delete_filesystem(filesystem)

    def extend_share(self, share, new_size, share_server=None):
        backend_share = self.client.get_share(share['id'],
                                              share['share_proto'])

        if not self._is_share_from_snapshot(backend_share):
            self.client.extend_filesystem(backend_share.filesystem,
                                          new_size)
        else:
            share_id = share['id']
            reason = ("Driver does not support extending a "
                      "snapshot based share.")
            raise exception.ShareExtendingError(share_id=share_id,
                                                reason=reason)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create snapshot from share."""
        share_name = snapshot['share_id']
        share_proto = snapshot['share']['share_proto']
        backend_share = self.client.get_share(share_name, share_proto)

        snapshot_name = snapshot['id']
        if self._is_share_from_snapshot(backend_share):
            self.client.create_snap_of_snap(backend_share.snap, snapshot_name)
        else:
            self.client.create_snapshot(backend_share.filesystem,
                                        snapshot_name)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        snap = self.client.get_snapshot(snapshot['id'])
        self.client.delete_snapshot(snap)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        # adding rules
        if add_rules:
            for rule in add_rules:
                self.allow_access(context, share, rule, share_server)

        # deleting rules
        if delete_rules:
            for rule in delete_rules:
                self.deny_access(context, share, rule, share_server)

        # recovery mode
        if not (add_rules or delete_rules):
            white_list = []
            for rule in access_rules:
                self.allow_access(context, share, rule, share_server)
                white_list.append(rule['access_to'])
            self.clear_access(share, white_list)

    def clear_access(self, share, white_list=None):
        share_proto = share['share_proto'].upper()
        share_name = share['id']
        if share_proto == 'CIFS':
            self.client.cifs_clear_access(share_name, white_list)
        elif share_proto == 'NFS':
            self.client.nfs_clear_access(share_name, white_list)

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share."""
        access_level = access['access_level']
        if access_level not in const.ACCESS_LEVELS:
            raise exception.InvalidShareAccessLevel(level=access_level)

        share_proto = share['share_proto'].upper()

        self._validate_share_protocol(share_proto)
        self._validate_share_access_type(share, access)

        if share_proto == 'CIFS':
            self._cifs_allow_access(share, access)
        elif share_proto == 'NFS':
            self._nfs_allow_access(share, access)

    def deny_access(self, context, share, access, share_server):
        """Deny access to a share."""
        share_proto = share['share_proto'].upper()

        self._validate_share_protocol(share_proto)
        self._validate_share_access_type(share, access)

        if share_proto == 'CIFS':
            self._cifs_deny_access(share, access)
        elif share_proto == 'NFS':
            self._nfs_deny_access(share, access)

    def ensure_share(self, context, share, share_server):
        """Ensure that the share is exported."""
        share_name = share['id']
        share_proto = share['share_proto']

        backend_share = self.client.get_share(share_name, share_proto)
        if not backend_share.existed:
            raise exception.ShareNotFound(share_id=share_name)

    def update_share_stats(self, stats_dict):
        """Communicate with EMCNASClient to get the stats."""
        stats_dict['driver_version'] = VERSION
        stats_dict['pools'] = []

        for pool in self.client.get_pool():
            if pool.name in self.pool_set:
                # the unit of following numbers are GB
                total_size = float(pool.size_total)
                used_size = float(pool.size_used)

                pool_stat = {
                    'pool_name': pool.name,
                    'thin_provisioning': True,
                    'total_capacity_gb': total_size,
                    'free_capacity_gb': total_size - used_size,
                    'allocated_capacity_gb': used_size,
                    'provisioned_capacity_gb': float(pool.size_subscribed),
                    'qos': False,
                    'reserved_percentage': self.reserved_percentage,
                    'max_over_subscription_ratio':
                        self.max_over_subscription_ratio,
                }
                stats_dict['pools'].append(pool_stat)

        if not stats_dict.get('pools'):
            message = _("Failed to update storage pool.")
            LOG.error(message)
            raise exception.EMCUnityError(err=message)

    def get_pool(self, share):
        """Get the pool name of the share."""
        backend_share = self.client.get_share(
            share['id'], share['share_proto'])

        return backend_share.filesystem.pool.name

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return self.IP_ALLOCATIONS

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""
        server_name = network_info['server_id']
        segmentation_id = network_info['segmentation_id']
        network = self.validate_network(network_info)
        mtu = network['mtu']
        tenant = self.client.get_tenant(network_info['server_id'],
                                        segmentation_id)

        sp_ports_map = unity_utils.find_ports_by_mtu(
            self.client.get_file_ports(),
            self.port_ids_conf, mtu)

        sp = self._choose_sp(sp_ports_map)
        nas_server = self.client.create_nas_server(server_name,
                                                   sp,
                                                   self.nas_server_pool,
                                                   tenant=tenant)
        sp = nas_server.home_sp
        port_id = self._choose_port(sp_ports_map, sp)
        try:
            self._create_network_interface(nas_server, network, port_id)

            self._handle_security_services(
                nas_server, network_info['security_services'])

            return {'share_server_name': server_name}

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Could not setup server.')
                server_details = {'share_server_name': server_name}
                self.teardown_server(
                    server_details, network_info['security_services'])

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        if not server_details:
            LOG.debug('Server details are empty.')
            return

        server_name = server_details.get('share_server_name')
        if not server_name:
            LOG.debug('No share server found for server %s.',
                      server_details.get('instance_id'))
            return

        username = None
        password = None
        for security_service in security_services:
            if security_service['type'] == 'active_directory':
                username = security_service['user']
                password = security_service['password']
                break

        self.client.delete_nas_server(server_name, username, password)

    def _cifs_allow_access(self, share, access):
        """Allow access to CIFS share."""
        self.client.cifs_allow_access(
            share['id'], access['access_to'], access['access_level'])

    def _cifs_deny_access(self, share, access):
        """Deny access to CIFS share."""
        self.client.cifs_deny_access(share['id'], access['access_to'])

    def _config_pool(self, pool_name):
        try:
            self.nas_server_pool = self.client.get_pool(pool_name)
        except storops_ex.UnityResourceNotFoundError:
            message = (_("The storage pools %s to store NAS server "
                         "configuration do not exist.") % pool_name)
            LOG.exception(message)
            raise exception.BadConfigurationException(reason=message)

    @staticmethod
    def validate_network(network_info):
        network = network_info['network_allocations'][0]
        if network['network_type'] not in SUPPORTED_NETWORK_TYPES:
            msg = _('The specified network type %s is unsupported by '
                    'the EMC Unity driver')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network['network_type'])
        return network

    def _create_network_interface(self, nas_server, network, port_id):
        kargs = {'ip_addr': network['ip_address'],
                 'gateway': network['gateway'],
                 'vlan_id': network['segmentation_id'],
                 'port_id': port_id}

        if netutils.is_valid_ipv6_cidr(kargs['ip_addr']):
            kargs['netmask'] = None
            kargs['prefix_length'] = str(utils.cidr_to_prefixlen(
                network['cidr']))
        else:
            kargs['netmask'] = utils.cidr_to_netmask(network['cidr'])

        # Create the interfaces on NAS server
        self.client.create_interface(nas_server, **kargs)

    def _choose_sp(self, sp_ports_map):
        sp = None
        if len(sp_ports_map.keys()) == 1:
            # Only one storage processor has usable ports,
            # create NAS server on that SP.
            sp = self.client.get_storage_processor(
                sp_id=list(sp_ports_map.keys())[0])
            LOG.debug('All the usable ports belong to  %s. '
                      'Creating NAS server on this SP without '
                      'load balance.', sp.get_id())
        return sp

    @staticmethod
    def _choose_port(sp_ports_map, sp):
        ports = sp_ports_map[sp.get_id()]
        return random.choice(list(ports))

    @staticmethod
    def _get_cifs_location(file_interfaces, share_name):
        return [
            {'path': r'\\%(interface)s\%(share_name)s' % {
                'interface': enas_utils.export_unc_path(interface.ip_address),
                'share_name': share_name}
             }
            for interface in file_interfaces
        ]

    def _get_managed_pools(self, pool_conf):
        # Get the real pools from the backend storage
        real_pools = set(pool.name for pool in self.client.get_pool())

        if not pool_conf:
            LOG.debug("No storage pool is specified, so all pools in storage "
                      "system will be managed.")
            return real_pools

        matched_pools, unmanaged_pools = unity_utils.do_match(real_pools,
                                                              pool_conf)

        if not matched_pools:
            msg = (_("All the specified storage pools to be managed "
                     "do not exist. Please check your configuration "
                     "emc_nas_pool_names in manila.conf. "
                     "The available pools in the backend are %s") %
                   ",".join(real_pools))
            raise exception.BadConfigurationException(reason=msg)

        if unmanaged_pools:
            LOG.info("The following specified storage pools "
                     "are not managed by the backend: "
                     "%(un_managed)s. This host will only manage "
                     "the storage pools: %(exist)s",
                     {'un_managed': ",".join(unmanaged_pools),
                      'exist': ",".join(matched_pools)})
        else:
            LOG.debug("Storage pools: %s will be managed.",
                      ",".join(matched_pools))

        return matched_pools

    @staticmethod
    def _get_nfs_location(file_interfaces, share_name):
        return [
            {'path': '%(interface)s:/%(share_name)s' % {
                'interface': enas_utils.convert_ipv6_format_if_needed(
                    interface.ip_address),
                'share_name': share_name}
             }
            for interface in file_interfaces
        ]

    @staticmethod
    def _get_pool_name_from_host(host):
        pool_name = share_utils.extract_host(host, level='pool')
        if not pool_name:
            message = (_("Pool is not available in the share host %s.") %
                       host)
            raise exception.InvalidHost(reason=message)

        return pool_name

    @staticmethod
    def _get_proto_enum(share_proto):
        share_proto = share_proto.upper()
        UnityStorageConnection._validate_share_protocol(share_proto)

        if share_proto == 'CIFS':
            return enums.FSSupportedProtocolEnum.CIFS
        elif share_proto == 'NFS':
            return enums.FSSupportedProtocolEnum.NFS

    @staticmethod
    def _get_server_name(share_server):
        if not share_server:
            msg = _('Share server not provided.')
            raise exception.InvalidInput(reason=msg)

        server_name = share_server.get(
            'backend_details', {}).get('share_server_name')

        if server_name is None:
            msg = (_("Name of the share server %s not found.")
                   % share_server['id'])
            LOG.error(msg)
            raise exception.InvalidInput(reason=msg)

        return server_name

    def _handle_security_services(self, nas_server, security_services):
        kerberos_enabled = False
        # Support 'active_directory' and 'kerberos'
        for security_service in security_services:
            service_type = security_service['type']
            if service_type == 'active_directory':
                # Create DNS server for NAS server
                domain = security_service['domain']
                dns_ip = security_service['dns_ip']
                self.client.create_dns_server(nas_server,
                                              domain,
                                              dns_ip)

                # Enable CIFS service
                username = security_service['user']
                password = security_service['password']
                self.client.enable_cifs_service(nas_server,
                                                domain=domain,
                                                username=username,
                                                password=password)
            elif service_type == 'kerberos':
                # Enable NFS service with kerberos
                kerberos_enabled = True
                # TODO(jay.xu): enable nfs service with kerberos
                LOG.warning('Kerberos is not supported by '
                            'EMC Unity manila driver plugin.')
            elif service_type == 'ldap':
                LOG.warning('LDAP is not supported by '
                            'EMC Unity manila driver plugin.')
            else:
                LOG.warning('Unknown security service type: %s.',
                            service_type)

        if not kerberos_enabled:
            # Enable NFS service without kerberos
            self.client.enable_nfs_service(nas_server)

    def _nfs_allow_access(self, share, access):
        """Allow access to NFS share."""
        self.client.nfs_allow_access(
            share['id'], access['access_to'], access['access_level'])

    def _nfs_deny_access(self, share, access):
        """Deny access to NFS share."""
        self.client.nfs_deny_access(share['id'], access['access_to'])

    @staticmethod
    def _is_isolated_filesystem(filesystem):
        filesystem.update()
        return (
            not filesystem.has_snap() and
            not (filesystem.cifs_share or filesystem.nfs_share)
        )

    @staticmethod
    def _is_share_from_snapshot(share):
        return True if share.snap else False

    @staticmethod
    def _validate_share_access_type(share, access):
        reason = None
        share_proto = share['share_proto'].upper()

        if share_proto == 'CIFS' and access['access_type'] != 'user':
            reason = _('Only user access type allowed for CIFS share.')
        elif share_proto == 'NFS' and access['access_type'] != 'ip':
            reason = _('Only IP access type allowed for NFS share.')

        if reason:
            raise exception.InvalidShareAccess(reason=reason)

    @staticmethod
    def _validate_share_protocol(share_proto):
        if share_proto not in ('NFS', 'CIFS'):
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.') %
                        share_proto))
