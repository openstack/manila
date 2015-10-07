# Copyright 2014 EMC Corporation.
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
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import units
import six

from manila.common import constants as const
from manila import db as manila_db
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW
from manila.share.drivers.emc.plugins import base as driver
from manila.share.drivers.emc.plugins.vnx import constants
from manila.share.drivers.emc.plugins.vnx import helper
from manila.share.drivers.emc.plugins.vnx import utils as vnx_utils
from manila import utils


VERSION = "1.0.0"

LOG = log.getLogger(__name__)


@vnx_utils.decorate_all_methods(vnx_utils.log_enter_exit,
                                debug_only=True)
class VNXStorageConnection(driver.StorageConnection):
    """Implements VNX specific functionality for EMC Manila driver."""

    @vnx_utils.log_enter_exit
    def __init__(self, *args, **kwargs):
        super(VNXStorageConnection, self).__init__(*args, **kwargs)
        self._mover_name = None
        self._pool_name = None
        self._pool = None
        self._filesystems = {}
        self.driver_handles_share_servers = True

    def create_share(self, context, share, share_server=None):
        """Is called to create share."""
        share_name = share['name']
        size = share['size'] * units.Ki
        vdm = self.share_server_validation(share_server)
        self._allocate_container(share_name, size, vdm['id'])

        if share['share_proto'] == 'NFS':
            location = self._create_nfs_share(share_name, vdm['name'],
                                              share_server)

        elif share['share_proto'] == 'CIFS':
            location = self._create_cifs_share(share_name, vdm)
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share['share_proto']))

        return location

    def share_server_validation(self, share_server):
        """Is called to validate the share server."""
        vdm_name = None
        vdm_id = None

        if share_server:
            backend_detail = share_server.get('backend_details')
            if backend_detail:
                vdm_name = backend_detail.get('share_server_name')
                vdm_id = backend_detail.get('share_server_id')

        if vdm_name is None or vdm_id is None:
            message = _("No share server found.")
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        return {'id': vdm_id, 'name': vdm_name}

    def _allocate_container(self, share_name, size, vdm_id):
        """Is called to allocate container for share."""
        status, out = self._XMLAPI_helper.create_file_system(
            share_name, size, self._pool['id'], vdm_id)
        if constants.STATUS_OK != status:
            message = _("Could not create file system for %s.") % share_name
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def _allocate_container_from_snapshot(self, share, snapshot, vdm_ref):
        """Is called to create share from snapshot."""
        self._replicate_snapshot(share, snapshot, self._mover_name, vdm_ref)

    @vnx_utils.log_enter_exit
    def _create_cifs_share(self, share_name, vdm):
        """Create cifs share."""
        # Get available CIFS Server and interface
        cifs_server = self._get_cifs_server_by_mover(vdm['id'])

        status, out = self._XMLAPI_helper.create_cifs_share(
            share_name, cifs_server['name'], vdm['id'])
        if constants.STATUS_OK != status:
            message = (_("Could not create CIFS share."
                         " Reason: %s.") % out)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)
        status, out = self._NASCmd_helper.disable_cifs_access(
            vdm['name'], share_name)
        if constants.STATUS_OK != status:
            message = _("Could not disable share access. Reason: %s.") % out
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        if len(cifs_server['interfaces']) == 0:
            message = (_("CIFS server %s doesn't have interface, "
                         "so the share is inaccessible.")
                       % cifs_server['name'])
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)
        interface = cifs_server['interfaces'][0]

        location = '\\\\%(interface)s\\%(name)s' % {'interface': interface,
                                                    'name': share_name}

        return location

    @vnx_utils.log_enter_exit
    def _create_nfs_share(self, share_name, vdm_name, share_server):
        """Is called to create nfs share."""
        status, out = self._NASCmd_helper.create_nfs_share(
            share_name, vdm_name)
        if constants.STATUS_OK != status:
            message = (_("Could not create NFS export for share %s.")
                       % share_name)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        return ('%(nfs_if)s:/%(share_name)s'
                % {'nfs_if': share_server['backend_details']['nfs_if'],
                   'share_name': share_name})

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        share_name = share['name']
        vdm_ref = self.share_server_validation(share_server)
        self._allocate_container_from_snapshot(share, snapshot, vdm_ref)

        if share['share_proto'] == 'NFS':
            self._create_nfs_share(share_name, vdm_ref['name'], share_server)
            location = ('%(nfs_if)s:/%(share_name)s'
                        % {'nfs_if': share_server['backend_details']['nfs_if'],
                           'share_name': share_name})
        elif share['share_proto'] == 'CIFS':
            location = self._create_cifs_share(share_name, vdm_ref)
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share['share_proto']))

        return location

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create snapshot from share."""

        ckpt_name = snapshot['name']

        fs_name = snapshot['share_name']

        filesystem = self._get_file_system_by_name(fs_name)
        status, out = self._XMLAPI_helper.create_check_point(filesystem['id'],
                                                             ckpt_name,
                                                             self._pool['id'])
        if constants.STATUS_ERROR == status:
            message = (_("Could not create check point. Reason: %s.")
                       % out['info'])
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def delete_share(self, context, share, share_server=None):
        """Is called to remove share."""
        if share_server is None:
            LOG.warn(_LW("Driver does not support share deletion without "
                         "share network specified. "
                         "Return directly because there is nothing to clean"))
            return

        if share['share_proto'] == 'NFS':
            self._delete_nfs_share(share, share_server)
        elif share['share_proto'] == 'CIFS':
            self._delete_cifs_share(share, share_server)
        else:
            raise exception.InvalidShare(
                reason='Unsupported share type')

    @vnx_utils.log_enter_exit
    def _delete_cifs_share(self, share, share_server):
        """Remove cifs share."""

        name = share['name']
        mover_name = self._get_vdm_name(share_server)
        mover_id = self._get_vdm_id(share_server)
        status, share_obj = self._XMLAPI_helper.get_cifs_share_by_name(name)
        if constants.STATUS_NOT_FOUND == status:
            LOG.warn(_LW("CIFS share %s not found. Skip the deletion"), name)
        else:
            mover_id = share_obj['mover']
            # Delete CIFS export
            status, out = self._XMLAPI_helper.delete_cifs_share(
                name,
                mover_id,
                share_obj['CifsServers'],
                share_obj['moverIdIsVdm'])
            if constants.STATUS_OK != status:
                error = (_("Deleting CIFS share %(share_name)s on "
                           "%(mover)s failed."
                           " Reason: %(err)s")
                         % {'share_name': name,
                            'mover': mover_name,
                            'err': out})
                LOG.error(error)
                raise exception.EMCVnxXMLAPIError(err=error)

        self._deallocate_container(name, mover_name, mover_id)

    @vnx_utils.log_enter_exit
    def _delete_nfs_share(self, share, share_server):
        """Remove nfs share."""
        name = share['name']
        path = '/' + name
        mover_name = self._get_vdm_name(share_server)
        mover_id = self._get_vdm_id(share_server)

        status, share_obj = self._NASCmd_helper.get_nfs_share_by_path(
            path,
            mover_name)
        if constants.STATUS_NOT_FOUND == status:
            LOG.warn(_LW("NFS share %s not found. Skip the deletion"), name)
        else:
            # Delete NFS export if it is present
            status, out = self._NASCmd_helper.delete_nfs_share(
                path, mover_name)
            if constants.STATUS_OK != status:
                error = (_("Deleting NFS share %(share_name)s on "
                           "%(mover_name)s failed. Reason: %(err)s")
                         % {'share_name': name,
                            'mover_name': mover_name,
                            'err': out})
                LOG.error(error)
                raise exception.EMCVnxXMLAPIError(err=error)

        self._deallocate_container(name, mover_name, mover_id)

    @vnx_utils.log_enter_exit
    def _deallocate_container(self, share_name, vdm_name, vdm_id=None):
        """Delete underneath objects of the share."""
        # Delete mount point
        name = share_name
        path = '/' + name
        if vdm_id is None:
            vdm = self._get_vdm_by_name(vdm_name, allow_absence=True)
            vdm_id = vdm['id'] if vdm else None

        if vdm_id is not None:
            status, out = self._XMLAPI_helper.delete_mount_point(
                vdm_id,
                path,
                'true')
            if constants.STATUS_OK != status:
                if self._XMLAPI_helper.is_mount_point_nonexistent(out):
                    LOG.warn(_LW("Mount point %(path)s on %(vdm)s not found."),
                             {'path': path, 'vdm': vdm_name})
                else:
                    LOG.warn(_LW("Deleting mount point %(path)s on "
                                 "%(mover_name)s failed. Reason: %(err)s"),
                             {'path': path,
                              'mover_name': vdm_name,
                              'err': out})
        else:
            LOG.warn(_LW("Failed to find the VDM. Try to "
                         "delete the file system"))

        self._delete_filesystem(name)

    @vnx_utils.log_enter_exit
    def _delete_filesystem(self, name):
        filesystem = self._get_file_system_by_name(name,
                                                   allow_absence=True)

        if not filesystem:
            LOG.warn(_LW("File system %s not found. Skip the deletion"), name)
            return

        # Delete file system
        status, out = self._XMLAPI_helper.delete_file_system(filesystem['id'])
        if constants.STATUS_OK != status:
            message = (_("Failed to delete file system %(fsid)s. "
                         "Reason: %(err)s.")
                       % {'fsid': filesystem['id'],
                          'err': out})
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Remove share's snapshot."""

        ckpt_name = snapshot['name']

        status, ckpt = self._XMLAPI_helper.get_check_point_by_name(ckpt_name)
        if constants.STATUS_OK != status:
            LOG.warn(_LW("Check point not found. Reason: %s."), status)
            return

        if ckpt['id'] == '':
            LOG.warn(_LW("Snapshot: %(name)s not found. "
                         "Skip the deletion.") % {'name': snapshot['name']})
            return

        status, out = self._XMLAPI_helper.delete_check_point(ckpt['id'])
        if constants.STATUS_OK != status:
            message = (_("Could not delete check point. Reason: %s.")
                       % out['info'])
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported."""
        pass

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        access_level = access['access_level']
        if access_level not in const.ACCESS_LEVELS:
            raise exception.InvalidShareAccessLevel(level=access_level)
        if share['share_proto'] == 'NFS':
            self._nfs_allow_access(context, share, access, share_server)
        elif share['share_proto'] == 'CIFS':
            self._cifs_allow_access(context, share, access, share_server)
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share['share_proto']))

    @vnx_utils.log_enter_exit
    def _cifs_allow_access(self, context, share, access, share_server):
        """Allow access to cifs share."""
        self._ensure_access_type_for_cifs(access)

        network_id = share['share_network_id']
        share_network = manila_db.share_network_get(context, network_id)
        security_services = share_network['security_services']
        self._ensure_security_service_for_cifs(security_services)

        share_name = share['name']
        mover_name = self._get_vdm_name(share_server)
        user_name = access['access_to']
        access_level = access['access_level']
        if access_level == const.ACCESS_LEVEL_RW:
            cifs_access = constants.CIFS_ACL_FULLCONTROL
        else:
            cifs_access = constants.CIFS_ACL_READ
        status, out = self._NASCmd_helper.allow_cifs_access(
            mover_name,
            share_name,
            user_name,
            security_services[0]['domain'],
            access=cifs_access)
        if constants.STATUS_OK != status:
            message = _("Could not allow CIFS access. Reason: %s.") % out
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    @vnx_utils.log_enter_exit
    def _nfs_allow_access(self, context, share, access, share_server):
        """Allow access to nfs share."""
        share_path = '/' + share['name']
        access_type = access['access_type']
        if access_type != 'ip':
            reason = _('Only ip access type allowed.')
            raise exception.InvalidShareAccess(reason)

        host_ip = access['access_to']
        access_level = access['access_level']
        mover_name = self._get_vdm_name(share_server)
        status, reason = self._NASCmd_helper.allow_nfs_share_access(
            share_path, host_ip, mover_name, access_level)
        if constants.STATUS_OK != status:
            message = (_("Could not allow access to NFS share. Reason: %s.")
                       % reason)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        if share['share_proto'] == 'NFS':
            self._nfs_deny_access(share, access, share_server)
        elif share['share_proto'] == 'CIFS':
            self._cifs_deny_access(context, share, access, share_server)
        else:
            raise exception.InvalidShare(
                reason=_('Unsupported share type'))

    @vnx_utils.log_enter_exit
    def _cifs_deny_access(self, context, share, access, share_server):
        """Deny access to cifs share."""
        self._ensure_access_type_for_cifs(access)

        network_id = share['share_network_id']
        share_network = manila_db.share_network_get(context, network_id)
        security_services = share_network['security_services']
        self._ensure_security_service_for_cifs(security_services)

        share_name = share['name']
        mover_name = self._get_vdm_name(share_server)
        user_name = access['access_to']
        access_level = access['access_level']
        if access_level == const.ACCESS_LEVEL_RW:
            cifs_access = constants.CIFS_ACL_FULLCONTROL
        else:
            cifs_access = constants.CIFS_ACL_READ
        status, out = self._NASCmd_helper.deny_cifs_access(
            mover_name,
            share_name,
            user_name,
            security_services[0]['domain'],
            access=cifs_access)
        if constants.STATUS_OK != status:
            message = (_("Could not deny access to CIFS share. Reason: %s.")
                       % out)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    @vnx_utils.log_enter_exit
    def _nfs_deny_access(self, share, access, share_server):
        """Deny access to nfs share."""
        share_path = '/' + share['name']
        access_type = access['access_type']
        if access_type != 'ip':
            reason = _('Only ip access type allowed.')
            raise exception.InvalidShareAccess(reason)

        host_ip = access['access_to']

        mover_name = self._get_vdm_name(share_server)
        status, reason = self._NASCmd_helper.deny_nfs_share_access(
            share_path, host_ip, mover_name)
        if constants.STATUS_OK != status:
            message = (_("Could not deny access to NFS share. Reason: %s.")
                       % reason)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def check_for_setup_error(self):
        """Check for setup error."""
        pass

    def connect(self, emc_share_driver, context):
        """Try to connect to VNX NAS server."""

        self._mover_name = (
            emc_share_driver.configuration.emc_nas_server_container)

        self._pool_name = emc_share_driver.configuration.emc_nas_pool_name

        configuration = emc_share_driver.configuration

        self._XMLAPI_helper = helper.XMLAPIHelper(configuration)
        self._NASCmd_helper = helper.NASCommandHelper(configuration)

        # To verify the input from manila configuration
        self._get_mover_ref_by_name(self._mover_name)
        self._pool = self._get_available_pool_by_name(self._pool_name)

    def update_share_stats(self, stats_dict):
        """Communicate with EMCNASClient to get the stats."""

        stats_dict['driver_version'] = VERSION

        pool = self._get_available_pool_by_name(self._pool_name)

        stats_dict['total_capacity_gb'] = pool['total_size']
        stats_dict['free_capacity_gb'] = (
            int(pool['total_size']) - int(pool['used_size']))

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs."""
        return constants.IP_ALLOCATIONS

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""
        # Only support single security service with type 'active_directory'
        interface_info = []
        vdm_name = 'vdm-' + network_info['server_id']
        vlan_id = network_info['segmentation_id']
        active_directory = None
        sec_services = []

        if network_info.get('security_services'):
            sec_services = network_info['security_services']
            is_valid, data = self._get_valid_security_service(
                sec_services)
            if is_valid:
                active_directory = data
            else:
                LOG.error(data)
                raise exception.EMCVnxXMLAPIError(err=data)

        try:
            # Refresh DataMover/VDM by the configuration
            moverRef = self._get_mover_ref_by_name(self._mover_name)
            if not self._vdm_exist(vdm_name):
                LOG.debug('Share server %s not found, creating.', vdm_name)
                self._create_vdm(vdm_name, moverRef)

            status, vdmRef = self._XMLAPI_helper.get_vdm_by_name(vdm_name)
            if constants.STATUS_OK != status:
                message = (_('Could not get share server by name %(name)s. '
                             'Reason: %(err)s.')
                           % {'name': vdm_name,
                              'err': vdmRef})
                LOG.error(message)
                raise exception.EMCVnxXMLAPIError(err=message)

            netmask = utils.cidr_to_netmask(network_info['cidr'])

            allocated_interfaces = []
            device_port = self._get_device_port(moverRef)

            for net_info in network_info['network_allocations']:
                ip = net_info['ip_address']
                if_name = 'if-' + net_info['id'][-12:]
                if_info = {'ip': ip, 'if_name': if_name}
                interface_info.append(if_info)
                status, interface = self._XMLAPI_helper.create_mover_interface(
                    if_name,
                    device_port['name'],
                    ip,
                    moverRef['id'],
                    netmask,
                    vlan_id)

                if constants.STATUS_OK != status:
                    message = (_('Interface creation failed. Reason: %s.')
                               % interface)
                    LOG.error(message)
                    raise exception.EMCVnxXMLAPIError(err=message)
                allocated_interfaces.append(interface)

            if active_directory:
                self._configure_active_directory(
                    active_directory, vdmRef,
                    allocated_interfaces[0])

            self._enable_nfs_service(vdmRef, allocated_interfaces[1])

            return {
                'share_server_name': vdm_name,
                'share_server_id': vdmRef['id'],
                'cifs_if': allocated_interfaces[0]['ip'],
                'nfs_if': allocated_interfaces[1]['ip'],
            }

        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Could not setup server. Reason: %s.'), ex)
                server_details = self._construct_backend_details(
                    vdm_name, vdmRef, interface_info)
                self.teardown_server(None, server_details, sec_services)

    def _construct_backend_details(self, vdm_name, vdmRef, interfaces):
        vdm_id = vdmRef['id'] if vdmRef else ""
        if_number = len(interfaces)
        cifs_if = interfaces[0]['ip'] if if_number > 0 else None
        nfs_if = interfaces[1]['ip'] if if_number > 1 else None

        return {
            'share_server_name': vdm_name,
            'share_server_id': vdm_id,
            'cifs_if': cifs_if,
            'nfs_if': nfs_if,
        }

    @vnx_utils.log_enter_exit
    def _vdm_exist(self, name, id=None):
        status, vdmRef = self._XMLAPI_helper.get_vdm_by_name(name)
        if constants.STATUS_OK != status:
            return False

        if id and vdmRef['id'] != id:
            return False

        return True

    def _create_vdm(self, vdm_name, moverRef):
        """Create a new VDM as a share sever."""

        status, out = self._XMLAPI_helper.create_vdm(vdm_name, moverRef['id'])
        if constants.STATUS_OK != status:
            message = _('Could not create VDM %s.') % vdm_name
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def _get_device_port(self, moverRef):
        """Get a proper network device to create interface."""

        status, mover = self._XMLAPI_helper.get_mover_by_id(moverRef['id'])
        if constants.STATUS_OK != status:
            message = (_("Could not get physical device port "
                         "on mover (id:%s).")
                       % moverRef['id'])
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        device_ports = mover['devices']

        return device_ports[0]

    def _configure_active_directory(self, security_service, vdmRef, interface):

        moverRef = self._get_mover_ref_by_name(self._mover_name)
        self._configure_dns(security_service, moverRef)

        data = {
            'mover_id': vdmRef['id'],
            'compName': vdmRef['name'],
            'netbios': vdmRef['name'][-14:],
            'domain': security_service['domain'],
            'admin_username': security_service['user'],
            'admin_password': security_service['password'],
            'interface': interface['ip'],
            'alias': [vdmRef['name'][-12:]],
        }

        status, out = self._XMLAPI_helper.create_cifs_server(data)
        if constants.STATUS_ERROR == status:
            message = (_('Failed to create cifs server %(name)s.'
                         'Reason: %(err)s.')
                       % {'name': data['compName'],
                          'err': out})
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def _configure_dns(self, security_service, moverRef):
        domain = security_service['domain']
        server = security_service['dns_ip']

        status, out = self._XMLAPI_helper.create_dns_domain(moverRef['id'],
                                                            domain,
                                                            server)
        if constants.STATUS_OK != status:
            message = _("Could not create DNS domain. Reason: %s.") % out
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

    def _enable_nfs_service(self, vdmRef, interface):

        self._NASCmd_helper.enable_nfs_service(vdmRef['name'],
                                               interface['name'])

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        if not server_details:
            LOG.debug('Server details are empty.')
            return

        vdm_name = server_details.get('share_server_name')
        if not vdm_name:
            LOG.debug('No share server found in server details.')
            return

        vdm_id = server_details.get('share_server_id')
        cifs_if = server_details.get('cifs_if')
        nfs_if = server_details.get('nfs_if')

        status, vdmRef = self._XMLAPI_helper.get_vdm_by_name(vdm_name)
        if constants.STATUS_OK != status or vdmRef['id'] != vdm_id:
            LOG.debug('Share server %s not found.', vdm_name)
            return

        self._disable_nfs_service(vdm_name)

        if security_services:
            # Only support single security service with type 'active_directory'
            is_valid, active_directory = self._get_valid_security_service(
                security_services)
            if is_valid and active_directory:
                status, cifs_servers = self._XMLAPI_helper.get_cifs_servers(
                    vdm_id)
                if constants.STATUS_OK != status:
                    LOG.error(_LE('Could not find CIFS server by name: %s.'),
                              vdm_name)

                for server in cifs_servers:
                    # Unjoin CIFS Server from domain
                    data = {
                        'name': server['name'],
                        'join_domain': 'false',
                        'admin_username': active_directory['user'],
                        'admin_password': active_directory['password'],
                        'mover_id': vdm_id,
                    }
                    self._XMLAPI_helper.modify_cifs_server(data)

                    # Delete CIFS Server
                    self._XMLAPI_helper.delete_cifs_server(server['name'],
                                                           vdm_id)

        # Delete interface from Data Mover
        if cifs_if:
            self._XMLAPI_helper.delete_mover_interface(
                cifs_if,
                vdmRef['host_mover_id'])

        if nfs_if:
            self._XMLAPI_helper.delete_mover_interface(
                nfs_if,
                vdmRef['host_mover_id'])

        # Delete Virtual Data Mover
        self._XMLAPI_helper.delete_vdm(vdmRef['id'])

    @vnx_utils.log_enter_exit
    def _disable_nfs_service(self, vdm_name):

        interfaces = self._NASCmd_helper.get_interfaces_by_vdm(vdm_name)

        for if_name in interfaces['vdm']:
            self._NASCmd_helper.disable_nfs_service(vdm_name, if_name)

    @vnx_utils.log_enter_exit
    def _get_available_pool_by_name(self, name):

        status, out = self._XMLAPI_helper.list_storage_pool()
        if constants.STATUS_OK != status:
            LOG.error(_LE("Could not get storage pool list."))

        for pool in out:
            if name == pool['name']:
                self._pool = pool
                break

        if self._pool is None:
            message = (_("Could not find the storage pool by name: %s.")
                       % name)
            LOG.error(message)
            raise exception.InvalidParameterValue(err=message)

        return self._pool

    def _get_mover_ref_by_name(self, name):
        status, mover = self._XMLAPI_helper.get_mover_ref_by_name(name)
        if constants.STATUS_ERROR == status:
            message = _("Could not find Data Mover by name: %s.") % name
            LOG.error(message)
            raise exception.InvalidParameterValue(err=message)

        return mover

    def _get_vdm_by_name(self, name, allow_absence=False):
        status, vdm = self._XMLAPI_helper.get_vdm_by_name(name)
        if constants.STATUS_OK != status:
            if allow_absence and constants.STATUS_NOT_FOUND == status:
                return None
            else:
                message = (_("Could not find Virtual Data Mover by name: %s.")
                           % name)
                LOG.error(message)
                raise exception.InvalidParameterValue(err=message)

        return vdm

    def _get_mover_by_id(self, mover_id):
        status, mover = self._XMLAPI_helper.get_mover_by_id(mover_id)
        if constants.STATUS_OK != status:
            message = _("Could not find Data Mover by id: %s.") % mover_id
            LOG.error(message)
            raise exception.InvalidParameterValue(err=message)

        return mover

    def _get_cifs_server_by_mover(self, mover_id):
        status, servers = self._XMLAPI_helper.get_cifs_servers(mover_id)
        if constants.STATUS_OK != status:
            message = _("Could not get CIFS server list for %s.") % mover_id
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        if len(servers) == 0:
            message = (_("Could not find the CIFS servers on VDM: %s.")
                       % mover_id)
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)

        return servers[0]

    def _get_file_system_by_name(self, name, allow_absence=False):

        status, filesystem = self._XMLAPI_helper.get_file_system_by_name(name)
        if constants.STATUS_OK != status:
            if allow_absence and constants.STATUS_NOT_FOUND == status:
                return None
            else:
                message = _("Could not get file system by name: %s.") % name
                LOG.error(message)
                raise exception.EMCVnxXMLAPIError(err=message)

        return filesystem

    def _replicate_snapshot(self, share, snapshot, mover_name, vdm_ref):

        # Source snapshot name
        ckpt_name = snapshot['name']

        # Source file system name
        source_share = snapshot['share_name']

        # Target file system name
        fs_name = share['name']

        fs_size = share['size'] * units.Ki

        interconn_id = self._NASCmd_helper.get_interconnect_id(
            mover_name, mover_name)
        # Run NAS command to copy ckpt to a fs
        status, msg = self._NASCmd_helper.create_fs_from_ckpt(
            fs_name,
            vdm_ref['name'],
            ckpt_name,
            source_share,
            self._pool['name'],
            interconn_id
        )
        if constants.STATUS_OK != status:
            message = _("Copy content from checkpoint to"
                        " file system failed. Reason: %s.") % msg
            LOG.error(message)
            raise exception.EMCVnxXMLAPIError(err=message)
        # Query the new created file system
        filesystem = self._get_file_system_by_name(fs_name)

        # Keep the compatibility for both Python2.x and Python 3.x
        if six.PY2:
            source_fs_size = long(filesystem['size'])
        else:
            source_fs_size = int(filesystem['size'])

        if source_fs_size < fs_size:
            status, out = self._XMLAPI_helper.extend_file_system(
                filesystem['id'],
                self._pool['id'],
                fs_size - source_fs_size
            )
            if constants.STATUS_OK != status:
                message = (_("Extend the file system failed. Reason: %s.")
                           % out)
                LOG.error(message)
                raise exception.EMCVnxXMLAPIError(err=message)

    def _get_mount_point_by_filesystem(self, filesystem, mover):
        status, out = self._XMLAPI_helper.get_mount_point(mover['id'])
        if constants.STATUS_OK != status:
            LOG.error(_LE("Could not get mount point. Reason: %s."), out)

        for mount in out:
            if mount['fs_id'] == filesystem['id']:
                return mount

    def _get_vdm_name(self, share_server):
        try:
            return share_server['backend_details']['share_server_name']
        except Exception:
            LOG.debug("Didn't get share server name from share_server %s",
                      share_server)
        return 'vdm-' + share_server['id']

    def _get_vdm_id(self, share_server):
        try:
            return share_server['backend_details']['share_server_id']
        except Exception:
            LOG.debug("Didn't get share server id from share_server %s",
                      share_server)
        return None

    def _get_valid_security_service(self, security_services):
        """Validate security services and return a supported security service.

        :param security_services:
        :return: (<is_valid>, <data>)
            <is_valid> is true to indicate security_services includes zero or
            single security service for active directory. Otherwise, it
            would return false.
            <data> return error message when <is_valid> is false. Otherwise,
            it will return zero or single security service for active
            directory.
        """

        # Only support single security service with type 'active_directory'
        service_number = len(security_services)
        if service_number == 0:
            return True, None

        if (service_number > 1 or
                security_services[0]['type'] != 'active_directory'):
            return False, _("Unsupported security services. "
                            "Only support single security service and "
                            "only support type 'active_directory'")

        return True, security_services[0]

    def _ensure_access_type_for_cifs(self, access):
        if access['access_type'] != 'user':
            msg = _('Only user access type allowed for cifs share')
            raise exception.EMCVnxXMLAPIError(err=msg)

    def _ensure_security_service_for_cifs(self, security_services):
        if (len(security_services) != 1 or
                security_services[0]['type'] != 'active_directory'):
            msg = _("Only single security service with "
                    "type 'active_directory' supported")
            raise exception.EMCVnxXMLAPIError(err=msg)
