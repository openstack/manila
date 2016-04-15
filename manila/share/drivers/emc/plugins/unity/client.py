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

import random
import six

from oslo_log import log
from oslo_utils import importutils

storops = importutils.try_import('storops')
if storops:
    from storops import exception as storops_ex
    from storops.unity import enums

from manila.common import constants as const
from manila import exception
from manila.i18n import _, _LI, _LE

LOG = log.getLogger(__name__)


class UnityClient(object):
    def __init__(self, host, username, password):
        if storops is None:
            LOG.error(_LE('StorOps is required to run EMC Unity driver.'))
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
                msg = _LE('Failed to enabled ACE for share: {}.')
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

    def create_filesystem(self, pool, nas_server, share_name, size, proto):
        try:
            return pool.create_filesystem(nas_server,
                                          share_name,
                                          size,
                                          proto=proto)
        except storops_ex.UnityFileSystemNameAlreadyExisted:
            LOG.debug('Filesystem %s already exists, '
                      'ignoring filesystem creation.', share_name)
            return self.system.get_filesystem(name=share_name)

    @staticmethod
    def delete_filesystem(filesystem):
        try:
            filesystem.delete()
        except storops_ex.UnityResourceNotFoundError:
            LOG.info(_LI('Filesystem %s is already removed.'), filesystem.name)

    def create_nas_server(self, name, sp, pool):
        try:
            return self.system.create_nas_server(name, sp, pool)
        except storops_ex.UnityNasServerNameUsedError:
            LOG.info(_LI('Share server %s already exists, ignoring share '
                         'server creation.'), name)
            return self.get_nas_server(name)

    def get_nas_server(self, name):
        try:
            return self.system.get_nas_server(name=name)
        except storops_ex.UnityResourceNotFoundError:
            LOG.info(_LI('NAS server %s not found.'), name)
            raise

    def delete_nas_server(self, name, username=None, password=None):
        try:
            nas_server = self.get_nas_server(name=name)
            nas_server.delete(username=username, password=password)
        except storops_ex.UnityResourceNotFoundError:
            LOG.info(_LI('NAS server %s not found.'), name)

    @staticmethod
    def create_dns_server(nas_server, domain, dns_ip):
        try:
            nas_server.create_dns_server(domain, dns_ip)
        except storops_ex.UnityOneDnsPerNasServerError:
            LOG.info(_LI('DNS server %s already exists, '
                         'ignoring DNS server creation.'), domain)

    @staticmethod
    def create_interface(nas_server, ip_addr, netmask, gateway, ports,
                         vlan_id=None):
        port_list = list(ports)
        random.shuffle(port_list)
        try:
            nas_server.create_file_interface(port_list[0],
                                             ip_addr,
                                             netmask=netmask,
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
            LOG.info(_LI('CIFS service on NAS server %s is '
                         'already enabled.'), nas_server.name)

    @staticmethod
    def enable_nfs_service(nas_server):
        try:
            nas_server.enable_nfs_service()
        except storops_ex.UnityNfsAlreadyEnabledError:
            LOG.info(_LI('NFS service on NAS server %s is '
                         'already enabled.'), nas_server.name)

    @staticmethod
    def create_snapshot(filesystem, name):
        access_type = enums.FilesystemSnapAccessTypeEnum.CHECKPOINT
        try:
            return filesystem.create_snap(name, fs_access_type=access_type)
        except storops_ex.UnitySnapNameInUseError:
            LOG.info(_LI('Snapshot %(snap)s on Filesystem %(fs)s already '
                         'exists.'), {'snap': name, 'fs': filesystem.name})

    def create_snap_of_snap(self, src_snap, dst_snap_name, snap_type):
        access_type = enums.FilesystemSnapAccessTypeEnum.PROTOCOL
        if snap_type == 'checkpoint':
            access_type = enums.FilesystemSnapAccessTypeEnum.CHECKPOINT

        if isinstance(src_snap, six.string_types):
            snap = self.get_snapshot(name=src_snap)
        else:
            snap = src_snap

        try:
            return snap.create_snap(dst_snap_name, fs_access_type=access_type)
        except storops_ex.UnitySnapNameInUseError:
            return self.get_snapshot(dst_snap_name)

    def get_snapshot(self, name):
        return self.system.get_snap(name=name)

    @staticmethod
    def delete_snapshot(snap):
        try:
            snap.delete()
        except storops_ex.UnityResourceNotFoundError:
            LOG.info(_LI('Snapshot %s is already removed.'), snap.name)

    def get_pool(self, name=None):
        return self.system.get_pool(name=name)

    def get_storage_processor(self, sp_id):
        sp = self.system.get_sp(sp_id)
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
            LOG.info(_LI('%(host)s access to %(share)s is already removed.'),
                     {'host': host_ip, 'share': share_name})

    def get_ip_ports(self, sp=None):
        ports = self.system.get_ip_port()
        link_up_ports = []
        for port in ports:
            if port.is_link_up and 'eth' in port.id:
                if sp and port.sp.id != sp.id:
                    continue

                link_up_ports.append(port)

        return link_up_ports
