# Copyright (c) 2014 EMC Corporation.
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
"""VNX backend for the EMC Manila driver."""

import copy
import random
import six

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import units

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.common.enas import constants
from manila.share.drivers.dell_emc.common.enas import utils as enas_utils
from manila.share.drivers.dell_emc.plugins import base as driver
from manila.share.drivers.dell_emc.plugins.vnx import object_manager as manager
from manila.share import utils as share_utils
from manila import utils

"""Version history:
    1.0.0 - Initial version (Liberty)
    2.0.0 - Bumped the version for Mitaka
    3.0.0 - Bumped the version for Ocata
    4.0.0 - Bumped the version for Pike
    5.0.0 - Bumped the version for Queens
"""
VERSION = "5.0.0"

LOG = log.getLogger(__name__)

VNX_OPTS = [
    cfg.StrOpt('vnx_server_container',
               deprecated_name='emc_nas_server_container',
               help='Data mover to host the NAS server.'),
    cfg.ListOpt('vnx_share_data_pools',
                deprecated_name='emc_nas_pool_names',
                help='Comma separated list of pools that can be used to '
                     'persist share data.'),
    cfg.ListOpt('vnx_ethernet_ports',
                deprecated_name='emc_interface_ports',
                help='Comma separated list of ports that can be used for '
                     'share server interfaces. Members of the list '
                     'can be Unix-style glob expressions.')
]

CONF = cfg.CONF
CONF.register_opts(VNX_OPTS)


@enas_utils.decorate_all_methods(enas_utils.log_enter_exit,
                                 debug_only=True)
class VNXStorageConnection(driver.StorageConnection):
    """Implements VNX specific functionality for EMC Manila driver."""

    @enas_utils.log_enter_exit
    def __init__(self, *args, **kwargs):
        super(VNXStorageConnection, self).__init__(*args, **kwargs)
        if 'configuration' in kwargs:
            kwargs['configuration'].append_config_values(VNX_OPTS)

        self.mover_name = None
        self.pools = None
        self.manager = None
        self.pool_conf = None
        self.reserved_percentage = None
        self.driver_handles_share_servers = True
        self.port_conf = None
        self.ipv6_implemented = True

    def create_share(self, context, share, share_server=None):
        """Create a share and export it based on protocol used."""
        share_name = share['id']
        size = share['size'] * units.Ki

        share_proto = share['share_proto']

        # Validate the share protocol
        if share_proto.upper() not in ('NFS', 'CIFS'):
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))

        # Get the pool name from share host field
        pool_name = share_utils.extract_host(share['host'], level='pool')
        if not pool_name:
            message = (_("Pool is not available in the share host %s.") %
                       share['host'])
            raise exception.InvalidHost(reason=message)

        # Validate share server
        self._share_server_validation(share_server)

        if share_proto == 'CIFS':
            vdm_name = self._get_share_server_name(share_server)
            server_name = vdm_name

            # Check if CIFS server exists.
            status, server = self._get_context('CIFSServer').get(server_name,
                                                                 vdm_name)
            if status != constants.STATUS_OK:
                message = (_("CIFS server %s not found.") % server_name)
                LOG.error(message)
                raise exception.EMCVnxXMLAPIError(err=message)

        self._allocate_container(share_name, size, share_server, pool_name)

        if share_proto == 'NFS':
            location = self._create_nfs_share(share_name, share_server)
        elif share_proto == 'CIFS':
            location = self._create_cifs_share(share_name, share_server)

        return location

    def _share_server_validation(self, share_server):
        """Validate the share server."""
        if not share_server:
            msg = _('Share server not provided')
            raise exception.InvalidInput(reason=msg)

        backend_details = share_server.get('backend_details')
        vdm = backend_details.get(
            'share_server_name') if backend_details else None

        if vdm is None:
            message = _("No share server found.")
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def _allocate_container(self, share_name, size, share_server, pool_name):
        """Allocate file system for share."""
        vdm_name = self._get_share_server_name(share_server)

        self._get_context('FileSystem').create(
            share_name, size, pool_name, vdm_name)

    def _allocate_container_from_snapshot(self, share, snapshot, share_server,
                                          pool_name):
        """Allocate file system from snapshot."""
        vdm_name = self._get_share_server_name(share_server)

        interconn_id = self._get_context('Mover').get_interconnect_id(
            self.mover_name, self.mover_name)

        self._get_context('FileSystem').create_from_snapshot(
            share['id'], snapshot['id'], snapshot['share_id'],
            pool_name, vdm_name, interconn_id)

        nwe_size = share['size'] * units.Ki
        self._get_context('FileSystem').extend(share['id'], pool_name,
                                               nwe_size)

    @enas_utils.log_enter_exit
    def _create_cifs_share(self, share_name, share_server):
        """Create CIFS share."""
        vdm_name = self._get_share_server_name(share_server)
        server_name = vdm_name

        # Get available CIFS Server and interface (one CIFS server per VDM)
        status, server = self._get_context('CIFSServer').get(server_name,
                                                             vdm_name)

        if 'interfaces' not in server or len(server['interfaces']) == 0:
            message = (_("CIFS server %s doesn't have interface, "
                         "so the share is inaccessible.")
                       % server['compName'])
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        interface = enas_utils.export_unc_path(server['interfaces'][0])

        self._get_context('CIFSShare').create(share_name, server['name'],
                                              vdm_name)

        self._get_context('CIFSShare').disable_share_access(share_name,
                                                            vdm_name)

        location = (r'\\%(interface)s\%(name)s' %
                    {'interface': interface, 'name': share_name})

        return location

    @enas_utils.log_enter_exit
    def _create_nfs_share(self, share_name, share_server):
        """Create NFS share."""
        vdm_name = self._get_share_server_name(share_server)

        self._get_context('NFSShare').create(share_name, vdm_name)

        nfs_if = enas_utils.convert_ipv6_format_if_needed(
            share_server['backend_details']['nfs_if'])

        return ('%(nfs_if)s:/%(share_name)s'
                % {'nfs_if': nfs_if,
                   'share_name': share_name})

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Create a share from a snapshot - clone a snapshot."""
        share_name = share['id']

        share_proto = share['share_proto']

        # Validate the share protocol
        if share_proto.upper() not in ('NFS', 'CIFS'):
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))

        # Get the pool name from share host field
        pool_name = share_utils.extract_host(share['host'], level='pool')
        if not pool_name:
            message = (_("Pool is not available in the share host %s.") %
                       share['host'])
            raise exception.InvalidHost(reason=message)

        self._share_server_validation(share_server)

        self._allocate_container_from_snapshot(
            share, snapshot, share_server, pool_name)

        nfs_if = enas_utils.convert_ipv6_format_if_needed(
            share_server['backend_details']['nfs_if'])

        if share_proto == 'NFS':
            self._create_nfs_share(share_name, share_server)
            location = ('%(nfs_if)s:/%(share_name)s'
                        % {'nfs_if': nfs_if,
                           'share_name': share_name})
        elif share_proto == 'CIFS':
            location = self._create_cifs_share(share_name, share_server)

        return location

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create snapshot from share."""
        share_name = snapshot['share_id']
        status, filesystem = self._get_context('FileSystem').get(share_name)
        if status != constants.STATUS_OK:
            message = (_("File System %s not found.") % share_name)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        pool_id = filesystem['pools_id'][0]

        self._get_context('Snapshot').create(snapshot['id'],
                                             snapshot['share_id'],
                                             pool_id)

    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        if share_server is None:
            LOG.warning("Driver does not support share deletion without "
                        "share network specified. Return directly because "
                        "there is nothing to clean.")
            return

        share_proto = share['share_proto']

        if share_proto == 'NFS':
            self._delete_nfs_share(share, share_server)
        elif share_proto == 'CIFS':
            self._delete_cifs_share(share, share_server)
        else:
            raise exception.InvalidShare(
                reason='Unsupported share type')

    @enas_utils.log_enter_exit
    def _delete_cifs_share(self, share, share_server):
        """Delete CIFS share."""
        vdm_name = self._get_share_server_name(share_server)

        name = share['id']

        self._get_context('CIFSShare').delete(name, vdm_name)

        self._deallocate_container(name, vdm_name)

    @enas_utils.log_enter_exit
    def _delete_nfs_share(self, share, share_server):
        """Delete NFS share."""
        vdm_name = self._get_share_server_name(share_server)

        name = share['id']

        self._get_context('NFSShare').delete(name, vdm_name)

        self._deallocate_container(name, vdm_name)

    @enas_utils.log_enter_exit
    def _deallocate_container(self, share_name, vdm_name):
        """Delete underneath objects of the share."""
        path = '/' + share_name

        try:
            # Delete mount point
            self._get_context('MountPoint').delete(path, vdm_name)
        except Exception:
            LOG.debug("Skip the failure of mount point %s deletion.", path)

        try:
            # Delete file system
            self._get_context('FileSystem').delete(share_name)
        except Exception:
            LOG.debug("Skip the failure of file system %s deletion.",
                      share_name)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot."""
        self._get_context('Snapshot').delete(snapshot['id'])

    def ensure_share(self, context, share, share_server=None):
        """Ensure that the share is exported."""

    def extend_share(self, share, new_size, share_server=None):
        # Get the pool name from share host field
        pool_name = share_utils.extract_host(share['host'], level='pool')
        if not pool_name:
            message = (_("Pool is not available in the share host %s.") %
                       share['host'])
            raise exception.InvalidHost(reason=message)

        share_name = share['id']

        self._get_context('FileSystem').extend(
            share_name, pool_name, new_size * units.Ki)

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to a share."""
        access_level = access['access_level']
        if access_level not in const.ACCESS_LEVELS:
            raise exception.InvalidShareAccessLevel(level=access_level)

        share_proto = share['share_proto']

        if share_proto == 'NFS':
            self._nfs_allow_access(context, share, access, share_server)
        elif share_proto == 'CIFS':
            self._cifs_allow_access(context, share, access, share_server)
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))

    @enas_utils.log_enter_exit
    def _cifs_allow_access(self, context, share, access, share_server):
        """Allow access to CIFS share."""
        vdm_name = self._get_share_server_name(share_server)
        share_name = share['id']

        if access['access_type'] != 'user':
            reason = _('Only user access type allowed for CIFS share')
            raise exception.InvalidShareAccess(reason=reason)

        user_name = access['access_to']

        access_level = access['access_level']
        if access_level == const.ACCESS_LEVEL_RW:
            cifs_access = constants.CIFS_ACL_FULLCONTROL
        else:
            cifs_access = constants.CIFS_ACL_READ

        # Check if CIFS server exists.
        server_name = vdm_name
        status, server = self._get_context('CIFSServer').get(server_name,
                                                             vdm_name)
        if status != constants.STATUS_OK:
            message = (_("CIFS server %s not found.") % server_name)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        self._get_context('CIFSShare').allow_share_access(
            vdm_name,
            share_name,
            user_name,
            server['domain'],
            access=cifs_access)

    @enas_utils.log_enter_exit
    def _nfs_allow_access(self, context, share, access, share_server):
        """Allow access to NFS share."""
        vdm_name = self._get_share_server_name(share_server)

        access_type = access['access_type']
        if access_type != 'ip':
            reason = _('Only ip access type allowed.')
            raise exception.InvalidShareAccess(reason=reason)

        host_ip = access['access_to']
        access_level = access['access_level']

        self._get_context('NFSShare').allow_share_access(
            share['id'], host_ip, vdm_name, access_level)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        # deleting rules
        for rule in delete_rules:
            self.deny_access(context, share, rule, share_server)

        # adding rules
        for rule in add_rules:
            self.allow_access(context, share, rule, share_server)

        # recovery mode
        if not (add_rules or delete_rules):
            white_list = []
            for rule in access_rules:
                self.allow_access(context, share, rule, share_server)
                white_list.append(
                    enas_utils.convert_ipv6_format_if_needed(
                        rule['access_to']))
            self.clear_access(share, share_server, white_list)

    def clear_access(self, share, share_server, white_list):
        share_proto = share['share_proto'].upper()
        share_name = share['id']
        if share_proto == 'CIFS':
            self._cifs_clear_access(share_name, share_server, white_list)
        elif share_proto == 'NFS':
            self._nfs_clear_access(share_name, share_server, white_list)

    @enas_utils.log_enter_exit
    def _cifs_clear_access(self, share_name, share_server, white_list):
        """Clear access for CIFS share except hosts in the white list."""
        vdm_name = self._get_share_server_name(share_server)

        # Check if CIFS server exists.
        server_name = vdm_name
        status, server = self._get_context('CIFSServer').get(server_name,
                                                             vdm_name)
        if status != constants.STATUS_OK:
            message = (_("CIFS server %(server_name)s has issue. "
                         "Detail: %(status)s") %
                       {'server_name': server_name, 'status': status})
            raise exception.EMCVnxXMLAPIError(err=message)

        self._get_context('CIFSShare').clear_share_access(
            share_name=share_name,
            mover_name=vdm_name,
            domain=server['domain'],
            white_list_users=white_list)

    @enas_utils.log_enter_exit
    def _nfs_clear_access(self, share_name, share_server, white_list):
        """Clear access for NFS share except hosts in the white list."""
        self._get_context('NFSShare').clear_share_access(
            share_name=share_name,
            mover_name=self._get_share_server_name(share_server),
            white_list_hosts=white_list)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to a share."""
        share_proto = share['share_proto']

        if share_proto == 'NFS':
            self._nfs_deny_access(share, access, share_server)
        elif share_proto == 'CIFS':
            self._cifs_deny_access(share, access, share_server)
        else:
            raise exception.InvalidShare(
                reason=_('Unsupported share type'))

    @enas_utils.log_enter_exit
    def _cifs_deny_access(self, share, access, share_server):
        """Deny access to CIFS share."""
        vdm_name = self._get_share_server_name(share_server)
        share_name = share['id']

        if access['access_type'] != 'user':
            reason = _('Only user access type allowed for CIFS share')
            raise exception.InvalidShareAccess(reason=reason)

        user_name = access['access_to']

        access_level = access['access_level']
        if access_level == const.ACCESS_LEVEL_RW:
            cifs_access = constants.CIFS_ACL_FULLCONTROL
        else:
            cifs_access = constants.CIFS_ACL_READ

        # Check if CIFS server exists.
        server_name = vdm_name
        status, server = self._get_context('CIFSServer').get(server_name,
                                                             vdm_name)
        if status != constants.STATUS_OK:
            message = (_("CIFS server %s not found.") % server_name)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        self._get_context('CIFSShare').deny_share_access(
            vdm_name,
            share_name,
            user_name,
            server['domain'],
            access=cifs_access)

    @enas_utils.log_enter_exit
    def _nfs_deny_access(self, share, access, share_server):
        """Deny access to NFS share."""
        vdm_name = self._get_share_server_name(share_server)

        access_type = access['access_type']
        if access_type != 'ip':
            reason = _('Only ip access type allowed.')
            raise exception.InvalidShareAccess(reason=reason)

        host_ip = enas_utils.convert_ipv6_format_if_needed(access['access_to'])

        self._get_context('NFSShare').deny_share_access(share['id'], host_ip,
                                                        vdm_name)

    def check_for_setup_error(self):
        """Check for setup error."""
        # To verify the input from Manila configuration
        status, out = self._get_context('Mover').get_ref(self.mover_name,
                                                         True)
        if constants.STATUS_ERROR == status:
            message = (_("Could not find Data Mover by name: %s.") %
                       self.mover_name)
            LOG.error(message)
            raise exception.InvalidParameterValue(err=message)

        self.pools = self._get_managed_storage_pools(self.pool_conf)

    def _get_managed_storage_pools(self, pools):
        matched_pools = set()
        if pools:
            # Get the real pools from the backend storage
            status, backend_pools = self._get_context('StoragePool').get_all()
            if status != constants.STATUS_OK:
                message = (_("Failed to get storage pool information. "
                             "Reason: %s") % backend_pools)
                LOG.error(message)
                raise exception.EMCVnxXMLAPIError(err=message)

            real_pools = set([item for item in backend_pools])
            conf_pools = set([item.strip() for item in pools])
            matched_pools, unmatched_pools = enas_utils.do_match_any(
                real_pools, conf_pools)

            if not matched_pools:
                msg = (_("None of the specified storage pools to be managed "
                         "exist. Please check your configuration "
                         "vnx_share_data_pools in manila.conf. "
                         "The available pools in the backend are %s.") %
                       ",".join(real_pools))
                raise exception.InvalidParameterValue(err=msg)

            LOG.info("Storage pools: %s will be managed.",
                     ",".join(matched_pools))
        else:
            LOG.debug("No storage pool is specified, so all pools "
                      "in storage system will be managed.")
        return matched_pools

    def connect(self, emc_share_driver, context):
        """Connect to VNX NAS server."""
        config = emc_share_driver.configuration
        config.append_config_values(VNX_OPTS)
        self.mover_name = config.vnx_server_container

        self.pool_conf = config.safe_get('vnx_share_data_pools')

        self.reserved_percentage = config.safe_get('reserved_share_percentage')
        if self.reserved_percentage is None:
            self.reserved_percentage = 0

        self.manager = manager.StorageObjectManager(config)
        self.port_conf = config.safe_get('vnx_ethernet_ports')

    def get_managed_ports(self):
        # Get the real ports(devices) list from the backend storage
        real_ports = self._get_physical_devices(self.mover_name)

        if not self.port_conf:
            LOG.debug("No ports are specified, so any of the ports on the "
                      "Data Mover can be used.")
            return real_ports

        matched_ports, unmanaged_ports = enas_utils.do_match_any(
            real_ports, self.port_conf)

        if not matched_ports:
            msg = (_("None of the specified network ports exist. "
                     "Please check your configuration vnx_ethernet_ports "
                     "in manila.conf. The available ports on the Data Mover "
                     "are %s.") %
                   ",".join(real_ports))
            raise exception.BadConfigurationException(reason=msg)

        LOG.debug("Ports: %s can be used.", ",".join(matched_ports))

        return list(matched_ports)

    def update_share_stats(self, stats_dict):
        """Communicate with EMCNASClient to get the stats."""
        stats_dict['driver_version'] = VERSION

        self._get_context('Mover').get_ref(self.mover_name, True)

        stats_dict['pools'] = []

        status, pools = self._get_context('StoragePool').get_all()
        for name, pool in pools.items():
            if not self.pools or pool['name'] in self.pools:
                total_size = float(pool['total_size'])
                used_size = float(pool['used_size'])

                pool_stat = dict(
                    pool_name=pool['name'],
                    total_capacity_gb=total_size,
                    free_capacity_gb=total_size - used_size,
                    qos=False,
                    reserved_percentage=self.reserved_percentage,
                )
                stats_dict['pools'].append(pool_stat)

        if not stats_dict['pools']:
            message = _("Failed to update storage pool.")
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def get_pool(self, share):
        """Get the pool name of the share."""
        share_name = share['id']
        status, filesystem = self._get_context('FileSystem').get(share_name)
        if status != constants.STATUS_OK:
            message = (_("File System %(name)s not found. "
                         "Reason: %(err)s") %
                       {'name': share_name, 'err': filesystem})
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        pool_id = filesystem['pools_id'][0]

        # Get the real pools from the backend storage
        status, backend_pools = self._get_context('StoragePool').get_all()
        if status != constants.STATUS_OK:
            message = (_("Failed to get storage pool information. "
                         "Reason: %s") % backend_pools)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        for name, pool_info in backend_pools.items():
            if pool_info['id'] == pool_id:
                return name

        available_pools = [item for item in backend_pools]
        message = (_("No matched pool name for share: %(share)s. "
                     "Available pools: %(pools)s") %
                   {'share': share_name, 'pools': available_pools})
        raise exception.EMCVnxXMLAPIError(err=message)

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return constants.IP_ALLOCATIONS

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""
        # Only support single security service with type 'active_directory'
        vdm_name = network_info['server_id']
        vlan_id = network_info['segmentation_id']
        active_directory = None
        allocated_interfaces = []

        if network_info.get('security_services'):
            is_valid, active_directory = self._get_valid_security_service(
                network_info['security_services'])

            if not is_valid:
                raise exception.EMCVnxXMLAPIError(err=active_directory)

        try:
            if not self._vdm_exist(vdm_name):
                LOG.debug('Share server %s not found, creating '
                          'share server...', vdm_name)
                self._get_context('VDM').create(vdm_name, self.mover_name)

            devices = self.get_managed_ports()

            for net_info in network_info['network_allocations']:
                random.shuffle(devices)

                ip_version = net_info['ip_version']

                interface = {
                    'name': net_info['id'][-12:],
                    'device_name': devices[0],
                    'ip': net_info['ip_address'],
                    'mover_name': self.mover_name,
                    'vlan_id': vlan_id if vlan_id else -1,
                }

                if ip_version == 6:
                    interface['ip_version'] = ip_version
                    interface['net_mask'] = six.text_type(
                        utils.cidr_to_prefixlen(network_info['cidr']))
                else:
                    interface['net_mask'] = utils.cidr_to_netmask(
                        network_info['cidr'])

                self._get_context('MoverInterface').create(interface)

                allocated_interfaces.append(interface)

            cifs_interface = allocated_interfaces[0]
            nfs_interface = allocated_interfaces[1]
            if active_directory:
                self._configure_active_directory(
                    active_directory, vdm_name, cifs_interface)

            self._get_context('VDM').attach_nfs_interface(
                vdm_name, nfs_interface['name'])

            return {
                'share_server_name': vdm_name,
                'cifs_if': cifs_interface['ip'],
                'nfs_if': nfs_interface['ip'],
            }

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Could not setup server.')
                server_details = self._construct_backend_details(
                    vdm_name, allocated_interfaces)
                self.teardown_server(
                    server_details, network_info['security_services'])

    def _construct_backend_details(self, vdm_name, interfaces):
        if_number = len(interfaces)
        cifs_if = interfaces[0]['ip'] if if_number > 0 else None
        nfs_if = interfaces[1]['ip'] if if_number > 1 else None

        return {
            'share_server_name': vdm_name,
            'cifs_if': cifs_if,
            'nfs_if': nfs_if,
        }

    @enas_utils.log_enter_exit
    def _vdm_exist(self, name):
        status, out = self._get_context('VDM').get(name)
        if constants.STATUS_OK != status:
            return False

        return True

    def _get_physical_devices(self, mover_name):
        """Get a proper network device to create interface."""
        devices = self._get_context('Mover').get_physical_devices(mover_name)
        if not devices:
            message = (_("Could not get physical device port on mover %s.") %
                       self.mover_name)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        return devices

    def _configure_active_directory(
            self, security_service, vdm_name, interface):

        domain = security_service['domain']
        server = security_service['dns_ip']

        self._get_context('DNSDomain').create(self.mover_name, domain, server)

        cifs_server_args = {
            'name': vdm_name,
            'interface_ip': interface['ip'],
            'domain_name': security_service['domain'],
            'user_name': security_service['user'],
            'password': security_service['password'],
            'mover_name': vdm_name,
            'is_vdm': True,
        }

        self._get_context('CIFSServer').create(cifs_server_args)

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        if not server_details:
            LOG.debug('Server details are empty.')
            return

        vdm_name = server_details.get('share_server_name')
        if not vdm_name:
            LOG.debug('No share server found in server details.')
            return

        cifs_if = server_details.get('cifs_if')
        nfs_if = server_details.get('nfs_if')

        status, vdm = self._get_context('VDM').get(vdm_name)
        if constants.STATUS_OK != status:
            LOG.debug('Share server %s not found.', vdm_name)
            return

        interfaces = self._get_context('VDM').get_interfaces(vdm_name)

        for if_name in interfaces['nfs']:
            self._get_context('VDM').detach_nfs_interface(vdm_name, if_name)

        if security_services:
            # Only support single security service with type 'active_directory'
            is_valid, active_directory = self._get_valid_security_service(
                security_services)
            if is_valid:
                status, servers = self._get_context('CIFSServer').get_all(
                    vdm_name)
                if constants.STATUS_OK != status:
                    LOG.error('Could not find CIFS server by name: %s.',
                              vdm_name)
                else:
                    cifs_servers = copy.deepcopy(servers)
                    for name, server in cifs_servers.items():
                        # Unjoin CIFS Server from domain
                        cifs_server_args = {
                            'name': server['name'],
                            'join_domain': False,
                            'user_name': active_directory['user'],
                            'password': active_directory['password'],
                            'mover_name': vdm_name,
                            'is_vdm': True,
                        }

                        try:
                            self._get_context('CIFSServer').modify(
                                cifs_server_args)
                        except exception.EMCVnxXMLAPIError as expt:
                            LOG.debug("Failed to modify CIFS server "
                                      "%(server)s. Reason: %(err)s.",
                                      {'server': server, 'err': expt})

                        self._get_context('CIFSServer').delete(name, vdm_name)

        # Delete interface from Data Mover
        if cifs_if:
            self._get_context('MoverInterface').delete(cifs_if,
                                                       self.mover_name)

        if nfs_if:
            self._get_context('MoverInterface').delete(nfs_if,
                                                       self.mover_name)

        # Delete Virtual Data Mover
        self._get_context('VDM').delete(vdm_name)

    def _get_valid_security_service(self, security_services):
        """Validate security services and return a supported security service.

        :param security_services:
        :returns: (<is_valid>, <data>) -- <is_valid> is true to indicate
            security_services includes zero or single security service for
            active directory. Otherwise, it would return false. <data> return
            error message when <is_valid> is false. Otherwise, it will
            return zero or single security service for active directory.
        """

        # Only support single security service with type 'active_directory'
        service_number = len(security_services)

        if (service_number > 1 or
                security_services[0]['type'] != 'active_directory'):
            return False, _("Unsupported security services. "
                            "Only support single security service and "
                            "only support type 'active_directory'")

        return True, security_services[0]

    def _get_share_server_name(self, share_server):
        try:
            return share_server['backend_details']['share_server_name']
        except Exception:
            LOG.debug("Didn't get share server name from share_server %s.",
                      share_server)
        return share_server['id']

    def _get_context(self, type):
        return self.manager.getStorageContext(type)
