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
import six

from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils

storops = importutils.try_import('storops')
if storops:
    from storops import exception as storops_ex
    from storops.unity import enums

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.common.enas import utils as enas_utils
from manila.share.drivers.dell_emc.plugins.unity import utils

LOG = log.getLogger(__name__)


class UnityClient(object):
    def __init__(self, host, username, password):
        if storops is None:
            LOG.error('StorOps is required to run EMC Unity driver.')
        self.system = storops.UnitySystem(host, username, password)

    def create_cifs_share(self, resource, share_name):
        """Create CIFS share from the resource.

        :param resource: either UnityFilesystem or UnitySnap object
        :param share_name: CIFS share name
        :return: UnityCifsShare object
        """
        try:
            share = resource.create_cifs_share(share_name)
            try:
                # bug on unity: the enable ace API has bug for snap
                # based share.  Log the internal error if it happens.
                share.enable_ace()
            except storops_ex.UnityException:
                msg = ('Failed to enabled ACE for share: {}.')
                LOG.exception(msg.format(share_name))
            return share
        except storops_ex.UnitySmbShareNameExistedError:
            return self.get_share(share_name, 'CIFS')

    def create_nfs_share(self, resource, share_name):
        """Create NFS share from the resource.

        :param resource: either UnityFilesystem or UnitySnap object
        :param share_name: NFS share name
        :return: UnityNfsShare object
        """
        try:
            return resource.create_nfs_share(share_name)
        except storops_ex.UnityNfsShareNameExistedError:
            return self.get_share(share_name, 'NFS')

    def create_nfs_filesystem_and_share(self, pool, nas_server,
                                        share_name, size_gb):
        """Create filesystem and share from pool/NAS server.

        :param pool: pool for file system creation
        :param nas_server: nas server for file system creation
        :param share_name: file system and share name
        :param size_gb: file system size
        """
        size = utils.gib_to_byte(size_gb)
        pool.create_nfs_share(
            nas_server, share_name, size, user_cap=True)

    def get_share(self, name, share_proto):
        # Validate the share protocol
        proto = share_proto.upper()

        if proto == 'CIFS':
            return self.system.get_cifs_share(name=name)
        elif proto == 'NFS':
            return self.system.get_nfs_share(name=name)
        else:
            raise exception.BadConfigurationException(
                reason=_('Invalid NAS protocol supplied: %s.') % share_proto)

    @staticmethod
    def delete_share(share):
        share.delete()

    def create_filesystem(self, pool, nas_server, share_name, size_gb, proto):
        try:
            size = utils.gib_to_byte(size_gb)
            return pool.create_filesystem(nas_server,
                                          share_name,
                                          size,
                                          proto=proto,
                                          user_cap=True)
        except storops_ex.UnityFileSystemNameAlreadyExisted:
            LOG.debug('Filesystem %s already exists, '
                      'ignoring filesystem creation.', share_name)
            return self.system.get_filesystem(name=share_name)

    @staticmethod
    def delete_filesystem(filesystem):
        try:
            filesystem.delete()
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('Filesystem %s is already removed.', filesystem.name)

    def create_nas_server(self, name, sp, pool, tenant=None):
        try:
            return self.system.create_nas_server(name, sp, pool,
                                                 tenant=tenant)
        except storops_ex.UnityNasServerNameUsedError:
            LOG.info('Share server %s already exists, ignoring share '
                     'server creation.', name)
            return self.get_nas_server(name)

    def get_nas_server(self, name):
        try:
            return self.system.get_nas_server(name=name)
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('NAS server %s not found.', name)
            raise

    def delete_nas_server(self, name, username=None, password=None):
        tenant = None
        try:
            nas_server = self.get_nas_server(name=name)
            tenant = nas_server.tenant
            nas_server.delete(username=username, password=password)
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('NAS server %s not found.', name)

        if tenant is not None:
            self._delete_tenant(tenant)

    @staticmethod
    def _delete_tenant(tenant):
        if tenant.nas_servers:
            LOG.debug('There are NAS servers belonging to the tenant %s. ',
                      'Do not delete it.',
                      tenant.get_id())
            return
        try:
            tenant.delete(delete_hosts=True)
        except storops_ex.UnityException as ex:
            LOG.warning('Delete tenant %(tenant)s failed with error: '
                        '%(ex)s. Leave the tenant on the system.',
                        {'tenant': tenant.get_id(),
                         'ex': ex})

    @staticmethod
    def create_dns_server(nas_server, domain, dns_ip):
        try:
            nas_server.create_dns_server(domain, dns_ip)
        except storops_ex.UnityOneDnsPerNasServerError:
            LOG.info('DNS server %s already exists, '
                     'ignoring DNS server creation.', domain)

    @staticmethod
    def create_interface(nas_server, ip_addr, netmask, gateway, port_id,
                         vlan_id=None, prefix_length=None):
        try:
            nas_server.create_file_interface(port_id,
                                             ip_addr,
                                             netmask=netmask,
                                             v6_prefix_length=prefix_length,
                                             gateway=gateway,
                                             vlan_id=vlan_id)
        except storops_ex.UnityIpAddressUsedError:
            raise exception.IPAddressInUse(ip=ip_addr)

    @staticmethod
    def enable_cifs_service(nas_server, domain, username, password):
        try:
            nas_server.enable_cifs_service(
                nas_server.file_interface,
                domain=domain,
                domain_username=username,
                domain_password=password)
        except storops_ex.UnitySmbNameInUseError:
            LOG.info('CIFS service on NAS server %s is '
                     'already enabled.', nas_server.name)

    @staticmethod
    def enable_nfs_service(nas_server):
        try:
            nas_server.enable_nfs_service()
        except storops_ex.UnityNfsAlreadyEnabledError:
            LOG.info('NFS service on NAS server %s is '
                     'already enabled.', nas_server.name)

    @staticmethod
    def create_snapshot(filesystem, name):
        access_type = enums.FilesystemSnapAccessTypeEnum.CHECKPOINT
        try:
            return filesystem.create_snap(name, fs_access_type=access_type)
        except storops_ex.UnitySnapNameInUseError:
            LOG.info('Snapshot %(snap)s on Filesystem %(fs)s already '
                     'exists.', {'snap': name, 'fs': filesystem.name})

    def create_snap_of_snap(self, src_snap, dst_snap_name):
        if isinstance(src_snap, six.string_types):
            snap = self.get_snapshot(name=src_snap)
        else:
            snap = src_snap

        try:
            return snap.create_snap(dst_snap_name)
        except storops_ex.UnitySnapNameInUseError:
            return self.get_snapshot(dst_snap_name)

    def get_snapshot(self, name):
        return self.system.get_snap(name=name)

    @staticmethod
    def delete_snapshot(snap):
        try:
            snap.delete()
        except storops_ex.UnityResourceNotFoundError:
            LOG.info('Snapshot %s is already removed.', snap.name)

    def get_pool(self, name=None):
        return self.system.get_pool(name=name)

    def get_storage_processor(self, sp_id=None):
        sp = self.system.get_sp(sp_id)
        if sp_id is None:
            # `sp` is a list of SPA and SPB.
            return [s for s in sp if s is not None and s.existed]
        else:
            return sp if sp.existed else None

    def cifs_clear_access(self, share_name, white_list=None):
        share = self.system.get_cifs_share(name=share_name)
        share.clear_access(white_list)

    def nfs_clear_access(self, share_name, white_list=None):
        share = self.system.get_nfs_share(name=share_name)
        share.clear_access(white_list, force_create_host=True)

    def cifs_allow_access(self, share_name, user_name, access_level):
        share = self.system.get_cifs_share(name=share_name)

        if access_level == const.ACCESS_LEVEL_RW:
            cifs_access = enums.ACEAccessLevelEnum.WRITE
        else:
            cifs_access = enums.ACEAccessLevelEnum.READ

        share.add_ace(user=user_name, access_level=cifs_access)

    def nfs_allow_access(self, share_name, host_ip, access_level):
        share = self.system.get_nfs_share(name=share_name)
        host_ip = enas_utils.convert_ipv6_format_if_needed(host_ip)
        if access_level == const.ACCESS_LEVEL_RW:
            share.allow_read_write_access(host_ip, force_create_host=True)
            share.allow_root_access(host_ip, force_create_host=True)
        else:
            share.allow_read_only_access(host_ip, force_create_host=True)

    def cifs_deny_access(self, share_name, user_name):
        share = self.system.get_cifs_share(name=share_name)

        share.delete_ace(user=user_name)

    def nfs_deny_access(self, share_name, host_ip):
        share = self.system.get_nfs_share(name=share_name)

        try:
            share.delete_access(host_ip)
        except storops_ex.UnityHostNotFoundException:
            LOG.info('%(host)s access to %(share)s is already removed.',
                     {'host': host_ip, 'share': share_name})

    def get_file_ports(self):
        ports = self.system.get_file_port()
        link_up_ports = []
        for port in ports:
            if port.is_link_up and self._is_external_port(port.id):
                link_up_ports.append(port)

        return link_up_ports

    def extend_filesystem(self, fs, new_size_gb):
        size = utils.gib_to_byte(new_size_gb)
        try:
            fs.extend(size, user_cap=True)
        except storops_ex.UnityNothingToModifyError:
            LOG.debug('The size of the file system %(id)s is %(size)s '
                      'bytes.', {'id': fs.get_id(), 'size': size})
        return size

    @staticmethod
    def _is_external_port(port_id):
        return 'eth' in port_id or '_la' in port_id

    def get_tenant(self, name, vlan_id):
        if not vlan_id:
            # Do not create vlan for flat network
            return None

        tenant = None
        try:
            tenant_name = "vlan_%(vlan_id)s_%(name)s" % {'vlan_id': vlan_id,
                                                         'name': name}
            tenant = self.system.create_tenant(tenant_name, vlans=[vlan_id])
        except (storops_ex.UnityVLANUsedByOtherTenantError,
                storops_ex.UnityTenantNameInUseError,
                storops_ex.UnityVLANAlreadyHasInterfaceError):
            with excutils.save_and_reraise_exception() as exc:
                tenant = self.system.get_tenant_use_vlan(vlan_id)
                if tenant is not None:
                    LOG.debug("The VLAN %s is already added into a tenant. "
                              "Use the existing VLAN tenant.", vlan_id)
                    exc.reraise = False
        except storops_ex.SystemAPINotSupported:
            LOG.info("This system doesn't support tenant.")

        return tenant
