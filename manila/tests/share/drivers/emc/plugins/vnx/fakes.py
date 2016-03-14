# Copyright (c) 2015 EMC Corporation.
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

import mock
from oslo_utils import units

from manila.common import constants as const
from manila.share import configuration as conf
from manila.tests import fake_share


def query(func):
    def inner(*args, **kwargs):
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<RequestPacket xmlns="http://www.emc.com/schemas/celerra/'
            'xml_api"><Request><Query>'
            + func(*args, **kwargs)
            + '</Query></Request></RequestPacket>'
        )

    return inner


def start_task(func):
    def inner(*args, **kwargs):
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<RequestPacket xmlns="http://www.emc.com/schemas/celerra/'
            'xml_api"><Request><StartTask timeout="300">'
            + func(*args, **kwargs)
            + '</StartTask></Request></RequestPacket>')

    return inner


def response(func):
    def inner(*args, **kwargs):
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<ResponsePacket xmlns="http://www.emc.com/schemas/celerra/'
            'xml_api"><Response>'
            + func(*args, **kwargs)
            + '</Response></ResponsePacket>'
        )

    return inner


class FakeData(object):
    # Share information
    share_id = '7cf7c200_d3af_4e05_b87e_9167c95df4f9'
    host = 'HostA@BackendB#fake_pool_name'
    share_name = share_id
    share_size = 10
    new_size = 20
    src_share_name = '7cf7c200_d3af_4e05_b87e_9167c95df4f0'

    # Snapshot information
    snapshot_name = 'de4c9050-e2f9-4ce1-ade4-5ed0c9f26451'
    src_snap_name = 'de4c9050-e2f9-4ce1-ade4-5ed0c9f26452'
    snapshot_id = 'fake_snap_id'
    snapshot_size = 10 * units.Ki

    # Share network information
    share_network_id = 'c5b3a865-56d0-4d88-abe5-879965e099c9'
    cidr = '192.168.1.0/24'
    segmentation_id = 100
    network_allocations_id1 = '132dbb10-9a36-46f2-8d89-3d909830c356'
    network_allocations_id2 = '7eabdeed-bad2-46ea-bd0f-a33884c869e0'
    network_allocations_ip1 = '192.168.1.1'
    network_allocations_ip2 = '192.168.1.2'
    domain_name = 'fake_domain'
    domain_user = 'administrator'
    domain_password = 'password'
    dns_ip_address = '192.168.1.200'

    # Share server information
    share_server_id = '56aafd02-4d44-43d7-b784-57fc88167224'

    # Filesystem information
    filesystem_name = share_name
    filesystem_id = 'fake_filesystem_id'
    filesystem_size = 10 * units.Ki
    filesystem_new_size = 20 * units.Ki

    # Mountpoint information
    path = '/' + share_name

    # Mover information
    mover_name = 'server_2'
    mover_id = 'fake_mover_id'
    interface_name1 = network_allocations_id1[-12:]
    interface_name2 = network_allocations_id2[-12:]
    long_interface_name = network_allocations_id1
    net_mask = '255.255.255.0'
    device_name = 'cge-1-0'
    interconnect_id = '2001'

    # VDM information
    vdm_name = share_server_id
    vdm_id = 'fake_vdm_id'

    # Pool information
    pool_name = 'fake_pool_name'
    pool_id = 'fake_pool_id'
    pool_used_size = 20480
    pool_total_size = 511999

    # NFS share access information
    rw_hosts = ['192.168.1.1', '192.168.1.2']
    ro_hosts = ['192.168.1.3', '192.168.1.4']
    nfs_host_ip = '192.168.1.5'

    fake_output = ''

    fake_error_msg = 'fake error message'

    emc_share_backend = 'vnx'
    emc_nas_server = '192.168.1.20'
    emc_nas_login = 'fakename'
    emc_nas_password = 'fakepassword'
    share_backend_name = 'EMC_NAS_Storage'


class StorageObjectTestData(object):
    def __init__(self):
        self.share_name = FakeData.share_name

        self.filesystem_name = FakeData.filesystem_name
        self.filesystem_id = FakeData.filesystem_id
        self.filesystem_size = 10 * units.Ki
        self.filesystem_new_size = 20 * units.Ki

        self.path = FakeData.path

        self.snapshot_name = FakeData.snapshot_name
        self.snapshot_id = FakeData.snapshot_id
        self.snapshot_size = 10 * units.Ki

        self.src_snap_name = FakeData.src_snap_name
        self.src_fileystems_name = FakeData.src_share_name

        self.mover_name = FakeData.mover_name
        self.mover_id = FakeData.mover_id
        self.vdm_name = FakeData.vdm_name
        self.vdm_id = FakeData.vdm_id

        self.pool_name = FakeData.pool_name
        self.pool_id = FakeData.pool_id
        self.pool_used_size = FakeData.pool_used_size
        self.pool_total_size = FakeData.pool_total_size

        self.interface_name1 = FakeData.interface_name1
        self.interface_name2 = FakeData.interface_name2
        self.long_interface_name = FakeData.long_interface_name
        self.ip_address1 = FakeData.network_allocations_ip1
        self.ip_address2 = FakeData.network_allocations_ip2
        self.net_mask = FakeData.net_mask
        self.vlan_id = FakeData.segmentation_id

        self.cifs_server_name = FakeData.vdm_name

        self.domain_name = FakeData.domain_name
        self.domain_user = FakeData.domain_user
        self.domain_password = FakeData.domain_password
        self.dns_ip_address = FakeData.dns_ip_address

        self.device_name = FakeData.device_name

        self.interconnect_id = FakeData.interconnect_id

        self.rw_hosts = FakeData.rw_hosts
        self.ro_hosts = FakeData.ro_hosts
        self.nfs_host_ip = FakeData.nfs_host_ip

        self.fake_output = FakeData.fake_output

    @response
    def resp_get_error(self):
        return (
            '<QueryStatus maxSeverity="error">'
            '<Problem messageCode="18522112101" facility="Generic" '
            'component="API" message="Fake message." severity="error">'
            '<Description>Fake description.</Description>'
            '<Action>Fake action.</Action>'
            '<Diagnostics>Fake diagnostics.</Diagnostics>'
            '</Problem>'
            '<Problem messageCode="18522112101" facility="Generic" '
            'component="API" message="Fake message." severity="error">'
            '<Description>Fake description.</Description>'
            '<Action>Fake action.</Action>'
            '<Diagnostics>Fake diagnostics.</Diagnostics>'
            '</Problem>'
            '</QueryStatus> '
        )

    @response
    def resp_get_without_value(self):
        return (
            '<QueryStatus maxSeverity="ok"/>'
        )

    @response
    def resp_task_succeed(self):
        return (
            '<TaskResponse taskId="123">'
            '<Status maxSeverity="ok"/>'
            '</TaskResponse>'
        )

    @response
    def resp_task_error(self):
        return (
            '<TaskResponse taskId="123">'
            '<Status maxSeverity="error"/>'
            '</TaskResponse>'
        )

    @response
    def resp_invalid_mover_id(self):
        return (
            '<Fault maxSeverity="error">'
            '<Problem messageCode="14227341323" facility="Prevalidator" '
            'component="API" message="Mover with id=100 not found." '
            'severity="error">'
            '<Description>The Mover ID supplied with the request is invalid.'
            '</Description>'
            '<Action>Refer to the XML API v2 schema/documentation and correct '
            'your user program logic.</Action>'
            '<Diagnostics> Exception tag: 14fb692e556 Exception '
            'message: com.emc.nas.ccmd.common.MessageInstanceImpl@5004000d '
            '</Diagnostics>'
            '</Problem>'
            '</Fault> '
        )


class FileSystemTestData(StorageObjectTestData):
    def __init__(self):
        super(FileSystemTestData, self).__init__()

    @start_task
    def req_create_on_vdm(self):
        return (
            '<NewFileSystem name="%(name)s">'
            '<Vdm vdm="%(id)s"/>'
            '<StoragePool mayContainSlices="true" pool="%(pool_id)s" '
            'size="%(size)s"/>'
            '</NewFileSystem>'
            % {'name': self.filesystem_name,
               'id': self.vdm_id,
               'pool_id': self.pool_id,
               'size': self.filesystem_size}
        )

    @start_task
    def req_create_on_mover(self):
        return (
            '<NewFileSystem name="%(name)s">'
            '<Mover mover="%(id)s"/>'
            '<StoragePool mayContainSlices="true" pool="%(pool_id)s" '
            'size="%(size)s"/>'
            '</NewFileSystem>'
            % {'name': self.filesystem_name,
               'id': self.mover_id,
               'pool_id': self.pool_id,
               'size': self.filesystem_size}
        )

    @response
    def resp_create_but_already_exist(self):
        return (
            ' <TaskResponse taskId="31362">'
            '<Status maxSeverity="error">'
            '<Problem messageCode="13691191325" component="APL" '
            'message="A file system with the name fake_filesystem '
            'already exists." severity="error">'
            '<Description></Description>'
            '<Action></Action>'
            '</Problem>'
            '</Status>'
            '</TaskResponse> '
        )

    @start_task
    def req_delete(self):
        return (
            '<DeleteFileSystem fileSystem="%(id)s"/>' %
            {'id': self.filesystem_id}
        )

    @response
    def resp_delete_but_failed(self):
        return (
            '<Fault maxSeverity="error">'
            '<Problem messageCode="14227341326" facility="Prevalidator" '
            'component="API" message="File system with id=77777 not found." '
            'severity="error">'
            '<Description>The file system ID supplied with the request is '
            'invalid.</Description>'
            '<Action>Refer to the XML API v2 schema/documentation and correct '
            'your user program logic.</Action>'
            '<Diagnostics> Exception tag: 14fb6b6a7b8 Exception '
            'message: com.emc.nas.ccmd.common.MessageInstanceImpl@5004000e '
            '</Diagnostics>'
            '</Problem>'
            '</Fault> '
        )

    @start_task
    def req_extend(self):
        return (
            '<ExtendFileSystem fileSystem="%(id)s">'
            '<StoragePool pool="%(pool_id)s" size="%(size)d"/>'
            '</ExtendFileSystem>' %
            {'id': self.filesystem_id,
             'pool_id': self.pool_id,
             'size': self.filesystem_new_size - self.filesystem_size}
        )

    @response
    def resp_extend_but_error(self):
        return (
            '<Fault maxSeverity="error">'
            '<Problem messageCode="14227341325" facility="Prevalidator" '
            'component="API" message="Fake message.">'
            '<Description>Fake description.</Description>'
            '<Action>Fake action.</Action>'
            '<Diagnostics> Fake diagnostics.</Diagnostics>'
            '</Problem>'
            '</Fault> '
        )

    @query
    def req_get(self):
        return (
            '<FileSystemQueryParams>'
            '<AspectSelection fileSystemCapacityInfos="true" '
            'fileSystems="true"/>'
            '<Alias name="%(name)s"/>'
            '</FileSystemQueryParams>' %
            {'name': self.filesystem_name}
        )

    @response
    def resp_get_succeed(self):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<FileSystem name="%(name)s" type="uxfs" volume="107" '
            'storagePools="%(pool_id)s" storages="1" containsSlices="true" '
            'internalUse="false" dataServicePolicies="Thin=No,Compressed=No,'
            'Mirrored=No,Tiering policy=Auto-Tier/Highest Available Tier" '
            'fileSystem="%(id)s">'
            '<ProductionFileSystemData cwormState="off"/>'
            '</FileSystem>'
            '<FileSystemCapacityInfo volumeSize="%(size)s" '
            'fileSystem="%(id)s"/>' %
            {'name': self.filesystem_name,
             'id': self.filesystem_id,
             'size': self.filesystem_size,
             'pool_id': self.pool_id}
        )

    @response
    def resp_get_but_miss_property(self):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<FileSystem name="%(name)s" type="uxfs" volume="107" '
            'storagePools="%(pool_id)s" storages="1" containsSlices="true" '
            'internalUse="false" '
            'fileSystem="%(id)s">'
            '<ProductionFileSystemData cwormState="off"/>'
            '</FileSystem>'
            '<FileSystemCapacityInfo volumeSize="%(size)s" '
            'fileSystem="%(id)s"/>' %
            {'name': self.filesystem_name,
             'id': self.filesystem_id,
             'size': self.filesystem_size,
             'pool_id': self.pool_id}
        )

    @response
    def resp_get_but_not_found(self):
        return (
            '<QueryStatus maxSeverity="warning">'
            '<Problem messageCode="18522112101" facility="Generic" '
            'component="API" message="The query may be incomplete or '
            'requested object not found." severity="warning">'
            '<Description>The query may be incomplete because some of the '
            'Celerra components are unavailable or do not exist. Another '
            'reason may be application error. </Description>'
            '<Action>If the entire Celerra is functioning correctly, '
            'check your client application logic. </Action>'
            '<Diagnostics>File system not found.</Diagnostics>'
            '</Problem>'
            '<Problem messageCode="18522112101" facility="Generic" '
            'component="API" message="The query may be incomplete or '
            'requested object not found." severity="warning">'
            '<Description>The query may be incomplete because some of the '
            'Celerra components are unavailable or do not exist. Another '
            'reason may be application error.</Description>'
            '<Action>If the entire Celerra is functioning correctly, '
            'check your client application logic.</Action>'
            '<Diagnostics>Migration file system not found.</Diagnostics>'
            '</Problem>'
            '</QueryStatus> '
        )

    def cmd_create_from_ckpt(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-name', self.filesystem_name,
            '-type', 'uxfs',
            '-create',
            'samesize=' + self.src_fileystems_name,
            'pool=' + self.pool_name,
            'storage=SINGLE',
            'worm=off',
            '-thin', 'no',
            '-option', 'slice=y',
        ]

    def cmd_copy_ckpt(self):
        session_name = self.filesystem_name + ':' + self.src_snap_name

        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_copy',
            '-name', session_name[0:63],
            '-source', '-ckpt', self.src_snap_name,
            '-destination', '-fs', self.filesystem_name,
            '-interconnect', "id=" + self.interconnect_id,
            '-overwrite_destination',
            '-full_copy',
        ]

    output_copy_ckpt = "OK"
    error_copy_ckpt = "ERROR"

    def cmd_nas_fs_info(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-info', self.filesystem_name,
        ]

    def output_info(self):
        return (
            """output = id        = 515
                name      = %(share_name)s
                acl       = 0
                in_use    = True
                type      = uxfs
                worm      = off
                volume    = v993
                deduplication   = Off
                thin_storage    = True
                tiering_policy  = Auto-Tier/Optimize Pool
                compressed= False
                mirrored  = False
                ckpts     = %(ckpt)s
                stor_devs = FNM00124500890-004B
                disks     = d7
                 disk=d7    fakeinfo""" %
            {'share_name': self.filesystem_name,
             'ckpt': self.snapshot_name})

    def cmd_delete(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-delete', self.snapshot_name,
            '-Force',
        ]


class SnapshotTestData(StorageObjectTestData):
    def __init__(self):
        super(SnapshotTestData, self).__init__()

    @start_task
    def req_create(self):
        return (
            '<NewCheckpoint checkpointOf="%(fsid)s" '
            'name="%(name)s"><SpaceAllocationMethod>'
            '<StoragePool pool="%(pool_id)s"/></SpaceAllocationMethod>'
            '</NewCheckpoint>'
            % {'fsid': self.filesystem_id,
               'name': self.snapshot_name,
               'pool_id': self.pool_id}
        )

    @start_task
    def req_create_with_size(self):
        return (
            '<NewCheckpoint checkpointOf="%(fsid)s" '
            'name="%(name)s"><SpaceAllocationMethod>'
            '<StoragePool pool="%(pool_id)s" size="%(size)s"/>'
            '</SpaceAllocationMethod>'
            '</NewCheckpoint>'
            % {'fsid': self.filesystem_id,
               'name': self.snapshot_name,
               'pool_id': self.pool_id,
               'size': self.snapshot_size}
        )

    @response
    def resp_create_but_already_exist(self):
        return (
            '<Status maxSeverity="error">'
            '<Problem messageCode="13690535947" component="APL" '
            'message="snap_0 is already in use." severity="error">'
            '<Description></Description>'
            '<Action></Action>'
            '</Problem>'
            '</Status>'
        )

    @query
    def req_get(self):
        return (
            '<CheckpointQueryParams><Alias name="%(name)s"/>'
            '</CheckpointQueryParams>'
            % {'name': self.snapshot_name}
        )

    @response
    def resp_get_succeed(self):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<Checkpoint checkpointOf="%(fs_id)s" name="%(name)s_replica1"'
            ' state="active" time="1405428355" fileSystemSize="0"'
            ' checkpoint="%(snap_id)s"/>'
            % {'name': self.snapshot_name,
               'fs_id': self.filesystem_id,
               'snap_id': self.snapshot_id}
        )

    @start_task
    def req_delete(self):
        return (
            '<DeleteCheckpoint checkpoint="%(id)s"/>' %
            {'id': self.snapshot_id}
        )


class MountPointTestData(StorageObjectTestData):
    def __init__(self):
        super(MountPointTestData, self).__init__()

    @start_task
    def req_create(self, mover_id, is_vdm=True):
        return (
            '<NewMount path="%(path)s" fileSystem="%(fs_id)s">'
            '<MoverOrVdm mover="%(mover_id)s" moverIdIsVdm="%(is_vdm)s"/>'
            '</NewMount>' %
            {'path': self.path,
             'fs_id': self.filesystem_id,
             'mover_id': mover_id,
             'is_vdm': 'true' if is_vdm else 'false'}
        )

    @response
    def resp_create_but_already_exist(self):
        return (
            '<TaskResponse taskId="31428">'
            '<Status maxSeverity="error">'
            '<Problem messageCode="13690601492" component="APL" '
            'message="Mount already exists" severity="error">'
            '<Description></Description> <Action></Action>'
            '</Problem>'
            '</Status>'
            '</TaskResponse> ')

    @start_task
    def req_delete(self, mover_id, is_vdm=True):
        return (
            '<DeleteMount path="%(path)s" mover="%(mover_id)s" '
            'moverIdIsVdm="%(is_vdm)s"/>' %
            {'path': self.path,
             'mover_id': mover_id,
             'is_vdm': 'true' if is_vdm else 'false'}
        )

    @response
    def resp_delete_but_nonexistent(self):
        return (
            '<TaskResponse taskId="31401">'
            '<Status maxSeverity="error"> <Problem messageCode="13690601492" '
            'component="APL" message="/fake_filesystem : No such path or '
            'invalid operation." severity="error">'
            '<Description></Description> <Action></Action>'
            '</Problem>'
            '</Status>'
            '</TaskResponse> '
        )

    @query
    def req_get(self, mover_id, is_vdm=True):
        return (
            '<MountQueryParams><MoverOrVdm mover="%(mover_id)s" '
            'moverIdIsVdm="%(is_vdm)s"/></MountQueryParams>' %
            {'mover_id': mover_id,
             'is_vdm': 'true' if is_vdm else 'false'}
        )

    @response
    def resp_get_succeed(self, mover_id, is_vdm=True):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<Mount fileSystem="%(fsID)s" disabled="false"'
            ' ntCredential="false" path="%(path)s" mover="%(mover_id)s"'
            ' moverIdIsVdm="%(is_vdm)s">'
            '<NfsOptions ro="false" virusScan="true"'
            ' prefetch="true" uncached="false"/>'
            '<CifsOptions cifsSyncwrite="false" notify="true"'
            ' triggerLevel="512" notifyOnAccess="false"'
            ' notifyOnWrite="false" oplock="true" accessPolicy="NATIVE"'
            ' lockingPolicy="nolock"/></Mount>'
            % {'path': self.path,
               'fsID': self.filesystem_id,
               'mover_id': mover_id,
               'is_vdm': 'true' if is_vdm else 'false'}
        )

    def cmd_server_mount(self, mode):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_mount', self.vdm_name,
            '-option', mode,
            self.filesystem_name,
            self.path,
        ]

    def cmd_server_umount(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_umount', self.vdm_name,
            '-perm', self.snapshot_name,
        ]


class VDMTestData(StorageObjectTestData):
    def __init__(self):
        super(VDMTestData, self).__init__()

    @start_task
    def req_create(self):
        return (
            '<NewVdm mover="%(mover_id)s" name="%(vdm_name)s"/>' %
            {'mover_id': self.mover_id, 'vdm_name': self.vdm_name}
        )

    @response
    def resp_create_but_already_exist(self):
        return (
            '<TaskResponse taskId="32551">'
            '<Status maxSeverity="error">'
            '<Problem messageCode="13421840550" component="CS_CORE" '
            'message="VDM_01 : an entry with this name already exists" '
            'severity="error">'
            '<Description>Duplicate name specified</Description>'
            '<Action>Specify a unqiue name</Action>'
            '</Problem>'
            '<Problem messageCode="13421840550" component="CS_CORE" '
            'message="VDM_01 : an entry with this name already exists" '
            'severity="error">'
            '<Description>Duplicate name specified</Description>'
            '<Action>Specify a unqiue name</Action>'
            '</Problem>'
            '</Status>'
            '</TaskResponse> '
        )

    @query
    def req_get(self):
        return '<VdmQueryParams/>'

    @response
    def resp_get_succeed(self, name=None):
        if not name:
            name = self.vdm_name

        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<Vdm name="%(vdm_name)s" state="loaded" mover="%(mover_id)s" '
            'rootFileSystem="396" vdm="%(vdm_id)s">'
            '<Status maxSeverity="ok"/>'
            '<Interfaces> <li>%(interface1)s</li> <li>%(interface2)s</li>'
            '</Interfaces> </Vdm>' %
            {'vdm_name': name,
             'vdm_id': self.vdm_id,
             'mover_id': self.mover_id,
             'interface1': self.interface_name1,
             'interface2': self.interface_name2}
        )

    @response
    def resp_get_but_not_found(self):
        return (
            '<QueryStatus maxSeverity="ok"/>'
        )

    @start_task
    def req_delete(self):
        return '<DeleteVdm vdm="%(vdmid)s"/>' % {'vdmid': self.vdm_id}

    def cmd_attach_nfs_interface(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-vdm', self.vdm_name,
            '-attach', self.interface_name2,
        ]

    def cmd_detach_nfs_interface(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-vdm', self.vdm_name,
            '-detach', self.interface_name2,
        ]

    def cmd_get_interfaces(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-i',
            '-vdm', self.vdm_name,
        ]

    def output_get_interfaces(self, cifs_interface=FakeData.interface_name1,
                              nfs_interface=FakeData.interface_name2):
        return (
            """id        = %(vdmid)s
            name      = %(name)s
            acl       = 0
            type      = vdm
            server    = server_2
            rootfs    = root_fs_vdm_vdm-fakeid
            I18N mode = UNICODE
            mountedfs =
            member_of =
            status    :
              defined = enabled
               actual = loaded, active
            Interfaces to services mapping:
             interface=%(nfs_if_name)s :vdm
             interface=%(cifs_if_name)s :cifs""" %
            {'vdmid': self.vdm_id,
             'name': self.vdm_name,
             'nfs_if_name': nfs_interface,
             'cifs_if_name': cifs_interface}
        )


class PoolTestData(StorageObjectTestData):
    def __init__(self):
        super(PoolTestData, self).__init__()

    @query
    def req_get(self):
        return (
            '<StoragePoolQueryParams/>'
        )

    @response
    def resp_get_succeed(self, name=None, id=None):
        if not name:
            name = self.pool_name
        if not id:
            id = self.pool_id
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<StoragePool movers="1 2" memberVolumes="98" storageSystems="1" '
            'name="fake" '
            'description="Mapped Pool Pool_2 on APM00152904560" '
            'mayContainSlicesDefault="true" diskType="Capacity" '
            'size="511999" usedSize="20480" autoSize="511999" '
            'virtualProvisioning="false" isHomogeneous="true" '
            'dataServicePolicies="Thin=No,Compressed=No,Mirrored=No,Tiering '
            'policy=Auto-Tier/Highest Available Tier" templatePool="59" '
            'stripeCount="5" stripeSize="256" pool="9">'
            '<SystemStoragePoolData dynamic="true" greedy="true" '
            'potentialAdditionalSize="0" isBackendPool="true"/>'
            '</StoragePool>'
            '<StoragePool movers="1 2" memberVolumes="98" storageSystems="1" '
            'name="%(name)s" '
            'description="Mapped Pool Pool_2 on APM00152904560" '
            'mayContainSlicesDefault="true" diskType="Capacity" '
            'size="411999" usedSize="%(pool_used_size)s" '
            'autoSize="%(pool_total_size)s" virtualProvisioning="false" '
            'isHomogeneous="true" '
            'dataServicePolicies="Thin=No,Compressed=No,Mirrored=No,Tiering '
            'policy=Auto-Tier/Highest Available Tier" templatePool="59" '
            'stripeCount="5" stripeSize="256" pool="%(id)s">'
            '<SystemStoragePoolData dynamic="true" greedy="true" '
            'potentialAdditionalSize="0" isBackendPool="true"/>'
            '</StoragePool>' %
            {'name': name,
             'id': id,
             'pool_used_size': self.pool_used_size,
             'pool_total_size': self.pool_total_size}
        )


class MoverTestData(StorageObjectTestData):
    def __init__(self):
        super(MoverTestData, self).__init__()

    @query
    def req_get_ref(self):
        return (
            '<MoverQueryParams>'
            '<AspectSelection movers="true"/>'
            '</MoverQueryParams>'
        )

    @response
    def resp_get_ref_succeed(self, name=None):
        if not name:
            name = self.mover_name
        return (
            '<QueryStatus maxSeverity="info">'
            '<Problem messageCode="18522112101" facility="Generic" '
            'component="API" message="The query may be incomplete or '
            'requested object not found." severity="warning">'
            '<Description>The query may be incomplete because some of the '
            'Celerra components are unavailable or do not exist. Another '
            'reason may be application error.</Description>'
            '<Action>If the entire Celerra is functioning correctly, '
            'check your client application logic.</Action>'
            '<Diagnostics>Standby Data Mover server_2.faulted.server_3 is '
            'out of service.</Diagnostics>'
            '</Problem>'
            '</QueryStatus>'
            '<Mover name="%(name)s" host="1" role="primary" standbys="2" '
            'i18NMode="UNICODE" failoverPolicy="auto" '
            'ntpServers="192.168.1.82" mover="%(id)s"/>'
            '<Mover name="server_3" host="2" role="standby" standbyFors="1" '
            'i18NMode="ASCII" failoverPolicy="none" mover="2"/>' %
            {'name': name, 'id': self.mover_id}
        )

    @query
    def req_get(self):
        return (
            '<MoverQueryParams mover="%(id)s">'
            '<AspectSelection moverInterfaces="true" moverStatuses="true" '
            'movers="true" moverNisDomains="true" moverNetworkDevices="true" '
            'moverDnsDomains="true" moverRoutes="true" '
            'moverDeduplicationSettings="true"/>'
            '</MoverQueryParams>' %
            {'id': self.mover_id}
        )

    @response
    def resp_get_succeed(self, name=None):
        if not name:
            name = self.mover_name
        return (
            '<QueryStatus maxSeverity="ok"/><Mover name="%(name)s" '
            'host="1" role="primary" i18NMode="UNICODE" failoverPolicy="none"'
            ' ntpServers="192.168.1.82" mover="%(id)s"/>'
            '<MoverStatus version="T8.1.3.34944" csTime="1406795150" '
            'clock="140681" timezone="GMT-5" uptime="85096" '
            'mover="%(id)s"><Status maxSeverity="ok"/>'
            '</MoverStatus>'
            '<MoverDnsDomain servers="192.168.1.82" protocol="udp" '
            'mover="%(id)s" name="win2012.openstack"/>'
            '<MoverInterface name="%(long_interface_name)s" device="mge0" '
            'ipVersion="IPv4" netMask="255.255.255.0" '
            'broadcastAddr="128.221.252.255" '
            'macAddr="0:60:16:53:cc:87" mtu="1500" up="true" vlanid="0" '
            'mover="%(id)s" ipAddress="128.221.252.1"/>'
            '<MoverInterface name="%(interface_name1)s" device="cge-2-0" '
            'ipVersion="IPv4" netMask="255.255.255.0" '
            'broadcastAddr="128.221.252.255" macAddr="0:60:16:53:cc:87" '
            'mtu="1500" up="true" vlanid="0" mover="%(id)s" '
            'ipAddress="128.221.252.2"/>'
            '<MoverInterface name="%(interface_name2)s" device="cge-2-1" '
            'ipVersion="IPv4" netMask="255.255.255.0" '
            'broadcastAddr="128.221.252.255" macAddr="0:60:16:53:cc:87" '
            'mtu="1500" up="true" vlanid="0" mover="%(id)s" '
            'ipAddress="128.221.252.3"/>'
            '<MoverRoute destination="0.0.0.0" interface="192.168.1.178" '
            'ipVersion="IPv4" netMask="0.0.0.0" '
            'gateway="192.168.1.217" mover="%(id)s"/>'
            '<LogicalNetworkDevice speed="auto" interfaces="192.168.1.136" '
            'type="physical-ethernet" mover="%(id)s" name="cge-2-0"/>'
            % {'id': self.mover_id,
               'name': name,
               'long_interface_name': self.long_interface_name[:31],
               'interface_name1': self.interface_name1,
               'interface_name2': self.interface_name2}
        )

    @start_task
    def req_create_interface(self,
                             if_name=FakeData.interface_name1,
                             ip=FakeData.network_allocations_ip1):
        return (
            '<NewMoverInterface name="%(if_name)s" vlanid="%(vlan)s" '
            'netMask="%(net_mask)s" device="%(device_name)s" '
            'mover="%(mover_id)s" ipAddress="%(ip)s"/>'
            % {'if_name': if_name,
               'vlan': self.vlan_id,
               'ip': ip,
               'mover_id': self.mover_id,
               'device_name': self.device_name,
               'net_mask': self.net_mask}
        )

    @response
    def resp_create_interface_but_name_already_exist(self):
        return (
            '<Status maxSeverity="error">'
            '<Problem messageCode="13421840550" component="CS_CORE" '
            'message="%(interface_name)s : an entry with this name already '
            'exists" severity="error">'
            '<Description>Duplicate name specified</Description>'
            '<Action>Specify a unqiue name</Action>'
            '</Problem>'
            '</Status>' % {'interface_name': self.interface_name1}
        )

    @response
    def resp_create_interface_but_ip_already_exist(self):
        return (
            '<Status maxSeverity="error">'
            '<Problem messageCode="13691781136" component="CS_CORE" '
            'message="Interface %(ip)s already exists."  severity="error">'
            '<Description></Description><Action></Action>'
            '</Problem>'
            '</Status>' % {'ip': self.ip_address1}
        )

    @response
    def resp_create_interface_with_conflicted_vlan_id(self):
        return (
            '<Status maxSeverity="error">'
            '<Problem messageCode="13421850371" component="CS_CORE" '
            'message="160: Invalid VLAN change. Other interfaces on this '
            'subnet are in a different VLAN." severity="error">'
            '<Description>The operation cannot complete because other '
            'interfaces on the same subnet are in a different VLAN. '
            'The Data Mover requires all interfaces in the same subnet '
            'to be in the same VLAN.</Description>'
            '<Action>Specify a VLAN to match other interfaces in the same '
            'subnet. To move multiple interfaces to a different VLAN, '
            'first set the VLAN id on each interface to 0, '
            'and then set their VLAN id\'s to the new VLAN number.</Action>'
            '</Problem>'
            '</Status>'
        )

    @start_task
    def req_delete_interface(self, ip=FakeData.network_allocations_ip1):

        return (
            '<DeleteMoverInterface mover="%(mover_id)s" '
            'ipAddress="%(ip)s"/>' %
            {'ip': ip,
             'mover_id': self.mover_id, }
        )

    @response
    def resp_delete_interface_but_nonexistent(self):
        return (
            '<Status maxSeverity="error">'
            '<Problem messageCode="13691781134" component="APL" '
            'message="Device 192.168.237.100 does not exist." '
            'severity="error">'
            '<Description></Description>'
            '<Action></Action>'
            '</Problem>'
            '</Status>'
        )

    def cmd_get_interconnect_id(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_cel',
            '-interconnect', '-l',
        ]

    def output_get_interconnect_id(self):
        return (
            'id name source_server destination_system destination_server\n'
            '%(id)s  loopback  %(src_server)s  nas149   %(dest_server)s\n' %
            {'id': self.interconnect_id,
             'src_server': self.mover_name,
             'dest_server': self.mover_name}
        )

    def cmd_get_physical_devices(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_sysconfig',
            self.mover_name, '-pci',
        ]

    def output_get_physical_devices(self):
        return (
            'server_2 : PCI DEVICES:\n'
            'On Board:\n'
            '  PMC QE8 Fibre Channel Controller\n'
            '    0:  fcp-0-0  IRQ: 20 addr: 5006016047a00245\n'
            '    0:  fcp-0-1  IRQ: 21 addr: 5006016147a00245\n'
            '    0:  fcp-0-2  IRQ: 22 addr: 5006016247a00245\n'
            '    0:  fcp-0-3  IRQ: 23 addr: 5006016347a00245\n'
            '  Broadcom Gigabit Ethernet Controller\n'
            '    0:  cge-1-0  IRQ: 24\n'
            '    speed=auto duplex=auto txflowctl=disable rxflowctl=disable\n'
            '    Link: Up\n'
            '    0:  cge-1-1  IRQ: 25\n'
            '    speed=auto duplex=auto txflowctl=disable rxflowctl=disable\n'
            '    Link: Down\n'
            '    0:  cge-1-2  IRQ: 26\n'
            '    speed=auto duplex=auto txflowctl=disable rxflowctl=disable\n'
            '    Link: Down\n'
            '    0:  cge-1-3  IRQ: 27\n'
            '    speed=auto duplex=auto txflowctl=disable rxflowctl=disable\n'
            '    Link: Down\n'
            'Slot: 4\n'
            '  PLX PCI-Express Switch  Controller\n'
            '    1:  PLX PEX8648  IRQ: 10\n'
        )


class DNSDomainTestData(StorageObjectTestData):
    def __init__(self):
        super(DNSDomainTestData, self).__init__()

    @start_task
    def req_create(self):
        return (
            '<NewMoverDnsDomain mover="%(mover_id)s" protocol="udp" '
            'name="%(domain_name)s" servers="%(server_ips)s"/>' %
            {'mover_id': self.mover_id,
             'domain_name': self.domain_name,
             'server_ips': self.dns_ip_address}
        )

    @start_task
    def req_delete(self):
        return (
            '<DeleteMoverDnsDomain mover="%(mover_id)s" '
            'name="%(domain_name)s"/>' %
            {'mover_id': self.mover_id,
             'domain_name': self.domain_name}
        )


class CIFSServerTestData(StorageObjectTestData):
    def __init__(self):
        super(CIFSServerTestData, self).__init__()

    @start_task
    def req_create(self, mover_id, is_vdm=True):
        return (
            '<NewW2KCifsServer interfaces="%(ip)s" compName="%(comp_name)s" '
            'name="%(name)s" domain="%(domain)s">'
            '<MoverOrVdm mover="%(mover_id)s" moverIdIsVdm="%(is_vdm)s"/>'
            '<Aliases><li>%(alias)s</li></Aliases>'
            '<JoinDomain userName="%(domain_user)s" '
            'password="%(domain_password)s"/>'
            '</NewW2KCifsServer>'
            % {'ip': self.ip_address1,
               'comp_name': self.cifs_server_name,
               'name': self.cifs_server_name[-14:],
               'mover_id': mover_id,
               'alias': self.cifs_server_name[-12:],
               'domain_user': self.domain_user,
               'domain_password': self.domain_password,
               'domain': self.domain_name,
               'is_vdm': 'true' if is_vdm else 'false'}
        )

    @query
    def req_get(self, mover_id, is_vdm=True):
        return (
            '<CifsServerQueryParams>'
            '<MoverOrVdm mover="%(mover_id)s" moverIdIsVdm="%(is_vdm)s"/>'
            '</CifsServerQueryParams>' %
            {'mover_id': mover_id,
             'is_vdm': 'true' if is_vdm else 'false'}
        )

    @response
    def resp_get_succeed(self, mover_id, is_vdm, join_domain):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<CifsServer interfaces="%(ip)s" type="W2K" '
            'localUsers="false" name="%(cifsserver)s" '
            'mover="%(mover_id)s" moverIdIsVdm="%(is_vdm)s"><Aliases>'
            '<li>%(alias)s</li></Aliases><W2KServerData domain='
            '"%(domain)s" compName="%(comp_name)s" '
            'domainJoined="%(join_domain)s"/></CifsServer>'
            % {'mover_id': mover_id,
               'cifsserver': self.cifs_server_name[-14:],
               'ip': self.ip_address1,
               'is_vdm': 'true' if is_vdm else 'false',
               'alias': self.cifs_server_name[-12:],
               'domain': self.domain_name,
               'join_domain': 'true' if join_domain else 'false',
               'comp_name': self.cifs_server_name}
        )

    @response
    def resp_get_without_interface(self, mover_id, is_vdm, join_domain):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<CifsServer interfaces="" type="W2K" localUsers="false" '
            'name="%(cifsserver)s" mover="%(mover_id)s" '
            'moverIdIsVdm="%(is_vdm)s">'
            '<Aliases><li>%(alias)s</li></Aliases>'
            '<W2KServerData domain="%(domain)s" compName="%(comp_name)s" '
            'domainJoined="%(join_domain)s"/></CifsServer>'
            % {'mover_id': mover_id,
               'cifsserver': self.cifs_server_name[-14:],
               'is_vdm': 'true' if is_vdm else 'false',
               'alias': self.cifs_server_name[-12:],
               'domain': self.domain_name,
               'join_domain': 'true' if join_domain else 'false',
               'comp_name': self.cifs_server_name}
        )

    @start_task
    def req_modify(self, mover_id, is_vdm=True, join_domain=False):
        return (
            '<ModifyW2KCifsServer mover="%(mover_id)s" '
            'moverIdIsVdm="%(is_vdm)s" name="%(cifsserver)s">'
            '<DomainSetting userName="%(username)s" password="%(pw)s" '
            'joinDomain="%(join_domain)s"/>'
            '</ModifyW2KCifsServer>'
            % {'mover_id': mover_id,
               'is_vdm': 'true' if is_vdm else 'false',
               'join_domain': 'true' if join_domain else 'false',
               'cifsserver': self.cifs_server_name[-14:],
               'username': self.domain_user,
               'pw': self.domain_password}
        )

    @response
    def resp_modify_but_already_join_domain(self):
        return (
            '<Status maxSeverity="error"> '
            '<Problem messageCode="13157007726" component="DART" '
            'message="Fake message." severity="error">'
            '<Description>Fake description</Description>'
            '<Action>Fake action.</Action>'
            '</Problem>'
            '</Status> '
        )

    @response
    def resp_modify_but_unjoin_domain(self):
        return (
            '<Status maxSeverity="error"> '
            '<Problem messageCode="13157007723" component="DART" '
            'message="Fake message." severity="error">'
            '<Description>Fake description</Description>'
            '<Action>Fake action.</Action>'
            '</Problem>'
            '</Status> '
        )

    @start_task
    def req_delete(self, mover_id, is_vdm=True):
        return (
            '<DeleteCifsServer mover="%(mover_id)s" moverIdIsVdm="%(is_vdm)s" '
            'name="%(cifsserver)s"/>'
            % {'mover_id': mover_id,
               'is_vdm': 'true' if is_vdm else 'false',
               'cifsserver': self.cifs_server_name[-14:]}
        )


class CIFSShareTestData(StorageObjectTestData):
    def __init__(self):
        super(CIFSShareTestData, self).__init__()

    @start_task
    def req_create(self, mover_id, is_vdm=True):
        return (
            '<NewCifsShare path="%(path)s" name="%(share_name)s">'
            '<MoverOrVdm mover="%(mover_id)s" moverIdIsVdm="%(is_vdm)s"/>'
            '<CifsServers><li>%(cifsserver)s</li></CifsServers>'
            '</NewCifsShare>' %
            {'path': '/' + self.share_name,
             'share_name': self.share_name,
             'mover_id': mover_id,
             'is_vdm': 'true' if is_vdm else 'false',
             'cifsserver': self.cifs_server_name[-14:]}
        )

    @start_task
    def req_delete(self, mover_id, is_vdm=True):
        return (
            '<DeleteCifsShare mover="%(mover_id)s" moverIdIsVdm="%(is_vdm)s" '
            'name="%(share_name)s">'
            '<CifsServers><li>%(cifsserver)s</li></CifsServers>'
            '</DeleteCifsShare>' %
            {'share_name': self.share_name,
             'mover_id': mover_id,
             'is_vdm': 'true' if is_vdm else 'false',
             'cifsserver': self.cifs_server_name[-12:]}
        )

    @query
    def req_get(self):
        return '<CifsShareQueryParams name="%s"/>' % self.share_name

    @response
    def resp_get_succeed(self, mover_id, is_vdm=True):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<CifsShare path="%(path)s" fileSystem="%(fsid)s" name="%(name)s" '
            'mover="%(moverid)s" moverIdIsVdm="%(is_vdm)s">'
            '<CifsServers><li>%(alias)s</li>'
            '</CifsServers>'
            '</CifsShare>' %
            {'path': self.path,
             'fsid': self.filesystem_id,
             'name': self.share_name,
             'moverid': mover_id,
             'is_vdm': 'true' if is_vdm else 'false',
             'alias': self.cifs_server_name[-12:]}
        )

    def cmd_disable_access(self):
        cmd_str = 'sharesd %s set noaccess' % self.share_name
        return [
            'env', 'NAS_DB=/nas',
            '/nas/bin/.server_config', self.vdm_name,
            '-v', '%s' % cmd_str,
        ]

    def cmd_change_access(self, access_level=const.ACCESS_LEVEL_RW,
                          action='grant'):
        account = self.domain_user + '@' + self.domain_name

        if access_level == const.ACCESS_LEVEL_RW:
            str_access = 'fullcontrol'
        else:
            str_access = 'read'

        allow_str = (
            'sharesd %(share_name)s %(action)s %(account)s=%(access)s'
            % {'share_name': self.share_name,
               'action': action,
               'account': account,
               'access': str_access}
        )
        return [
            'env', 'NAS_DB=/nas',
            '/nas/bin/.server_config', self.vdm_name,
            '-v', '%s' % allow_str,
        ]

    def output_allow_access(self):
        return (
            "Command succeeded:  :3 sharesd %(share)s grant             "
            "%(user)s@%(domain)s=fullcontrol"
            % {'share': self.share_name,
               'user': self.domain_user,
               'domain': self.domain_name}
        )

    def output_allow_access_but_duplicate_ace(self):
        return (
            '%(vdm_name)s : commands processed: 1'
            'output is complete'
            '1443422844: SMB: 6: ACE for %(domain)s\\%(user)s '
            'unchanged'
            '1443422844: ADMIN: 3: '
            'Command failed:  :23 '
            'sharesd %(share)s grant %(user)s@%(domain)s=read'
            'Error 4020: %(vdm_name)s : failed to complete command"'
            % {'share': self.share_name,
               'user': self.domain_user,
               'domain': self.domain_name,
               'vdm_name': self.vdm_name}
        )

    def output_deny_access_but_no_ace(self):
        return (
            '%(vdm_name)s : commands processed: 1'
            'output is complete'
            '1443515516: SMB: 6: No ACE found for %(domain)s\\%(user)s '
            '1443515516: ADMIN: 3: '
            'Command failed:  :26 '
            'sharesd %(share)s revoke %(user)s@%(domain)s=read'
            'Error 4020: %(vdm_name)s : failed to complete command"'
            % {'share': self.share_name,
               'user': self.domain_user,
               'domain': self.domain_name,
               'vdm_name': self.vdm_name}
        )

    def output_deny_access_but_no_user_found(self):
        return (
            '%(vdm_name)s : commands processed: 1'
            'output is complete'
            '1443520322: SMB: 6: Cannot get mapping for %(domain)s\\%(user)s '
            '1443520322: ADMIN: 3: '
            'Command failed:  :26 '
            'sharesd %(share)s revoke %(user)s@%(domain)s=read'
            'Error 4020: %(vdm_name)s : failed to complete command"'
            % {'share': self.share_name,
               'user': self.domain_user,
               'domain': self.domain_name,
               'vdm_name': self.vdm_name}
        )


class NFSShareTestData(StorageObjectTestData):
    def __init__(self):
        super(NFSShareTestData, self).__init__()

    def cmd_create(self):
        default_access = 'access=-0.0.0.0/0.0.0.0'
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', self.vdm_name,
            '-option', default_access,
            self.path,
        ]

    def output_create(self):
        return "%s : done" % self.vdm_name

    def cmd_get(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', self.vdm_name,
            '-P', 'nfs',
            '-list', self.path,
        ]

    def output_get_succeed(self, rw_hosts, ro_hosts):
        if rw_hosts and ro_hosts:
            return (
                '%(mover_name)s :\nexport "%(path)s" '
                'access=-0.0.0.0/0.0.0.0:%(host)s root=%(host)s '
                'rw=%(rw_host)s ro=%(ro_host)s\n'
                % {'mover_name': self.vdm_name,
                   'path': self.path,
                   'host': ":".join(rw_hosts + ro_hosts),
                   'rw_host': ":".join(rw_hosts),
                   'ro_host': ":".join(ro_hosts)}
            )
        elif rw_hosts:
            return (
                '%(mover_name)s :\nexport "%(path)s" '
                'access=-0.0.0.0/0.0.0.0:%(host)s root=%(host)s '
                'rw=%(rw_host)s\n'
                % {'mover_name': self.vdm_name,
                   'host': rw_hosts,
                   'path': self.path,
                   'rw_host': ":".join(rw_hosts)}
            )
        elif ro_hosts:
            return (
                '%(mover_name)s :\nexport "%(path)s" '
                'access=-0.0.0.0/0.0.0.0:%(host)s root=%(host)s '
                'ro=%(ro_host)s\n'
                % {'mover_name': self.vdm_name,
                   'host': ro_hosts,
                   'path': self.path,
                   'ro_host': ":".join(ro_hosts)}
            )
        else:
            return (
                '%(mover_name)s :\nexport "%(path)s" '
                'access=-0.0.0.0/0.0.0.0\n'
                % {'mover_name': self.vdm_name,
                   'path': self.path}
            )

    def output_get_but_not_found(self):
        return (
            '%(mover_name)s : \nError 2: %(mover_name)s : '
            'No such file or directory \n' % {'mover_name': self.vdm_name}
        )

    def cmd_delete(self):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', self.vdm_name,
            '-unexport',
            '-perm',
            self.path,
        ]

    def output_delete_succeed(self):
        return "%s : done" % self.vdm_name

    def output_delete_but_locked(self):
        return ("Error 2201: %s : unable to acquire lock(s), try later"
                % self.vdm_name)

    def cmd_set_access(self, rw_hosts, ro_hosts):
        access_str = ("access=-0.0.0.0/0.0.0.0:%(access_hosts)s,"
                      "root=%(root_hosts)s,rw=%(rw_hosts)s,ro=%(ro_hosts)s" %
                      {'rw_hosts': ":".join(rw_hosts),
                       'ro_hosts': ":".join(ro_hosts),
                       'root_hosts': ":".join(rw_hosts + ro_hosts),
                       'access_hosts': ":".join(rw_hosts + ro_hosts)})

        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', self.vdm_name,
            '-ignore',
            '-option', access_str,
            self.path,
        ]

    def output_set_access_success(self):
        return "%s : done" % self.vdm_name


class FakeEMCShareDriver(object):
    def __init__(self):
        self.configuration = conf.Configuration(None)
        self.configuration.append_config_values = mock.Mock(return_value=0)
        self.configuration.emc_share_backend = FakeData.emc_share_backend
        self.configuration.emc_nas_server_container = FakeData.mover_name
        self.configuration.emc_nas_server = FakeData.emc_nas_server
        self.configuration.emc_nas_login = FakeData.emc_nas_login
        self.configuration.emc_nas_password = FakeData.emc_nas_password
        self.configuration.share_backend_name = FakeData.share_backend_name

CIFS_SHARE = fake_share.fake_share(
    id=FakeData.share_id,
    name=FakeData.share_name,
    size=FakeData.share_size,
    share_network_id=FakeData.share_network_id,
    share_server_id=FakeData.share_server_id,
    host=FakeData.host,
    share_proto='CIFS')

NFS_SHARE = fake_share.fake_share(
    id=FakeData.share_id,
    name=FakeData.share_name,
    size=FakeData.share_size,
    share_network_id=FakeData.share_network_id,
    share_server_id=FakeData.share_server_id,
    host=FakeData.host,
    share_proto='NFS')

CIFS_RW_ACCESS = fake_share.fake_access(
    access_type='user',
    access_to=FakeData.domain_user,
    access_level='rw')

CIFS_RO_ACCESS = fake_share.fake_access(
    access_type='user',
    access_to=FakeData.domain_user,
    access_level='ro')

NFS_RW_ACCESS = fake_share.fake_access(
    access_type='ip',
    access_to=FakeData.nfs_host_ip,
    access_level='rw')

NFS_RO_ACCESS = fake_share.fake_access(
    access_type='ip',
    access_to=FakeData.nfs_host_ip,
    access_level='ro')

SHARE_SERVER = {
    'id': FakeData.share_server_id,
    'share_network': {
        'name': 'fake_share_network',
        'id': FakeData.share_network_id
    },
    'share_network_id': FakeData.share_network_id,
    'backend_details': {
        'share_server_name': FakeData.vdm_name,
        'cifs_if': FakeData.network_allocations_ip1,
        'nfs_if': FakeData.network_allocations_ip2,
    }
}

SERVER_DETAIL = {
    'share_server_name': FakeData.vdm_name,
    'cifs_if': FakeData.network_allocations_ip1,
    'nfs_if': FakeData.network_allocations_ip2,
}

SECURITY_SERVICE = [
    {
        'type': 'active_directory',
        'domain': FakeData.domain_name,
        'dns_ip': FakeData.dns_ip_address,
        'user': FakeData.domain_user,
        'password': FakeData.domain_password
    },
]

NETWORK_INFO = {
    'server_id': FakeData.share_server_id,
    'cidr': FakeData.cidr,
    'security_services': [
        {'type': 'active_directory',
         'domain': FakeData.domain_name,
         'dns_ip': FakeData.dns_ip_address,
         'user': FakeData.domain_user,
         'password': FakeData.domain_password},
    ],
    'segmentation_id': FakeData.segmentation_id,
    'network_type': 'vlan',
    'network_allocations': [
        {'id': FakeData.network_allocations_id1,
         'ip_address': FakeData.network_allocations_ip1},
        {'id': FakeData.network_allocations_id2,
         'ip_address': FakeData.network_allocations_ip2}
    ]
}

STATS = dict(
    share_backend_name='VNX',
    vendor_name='EMC',
    storage_protocol='NFS_CIFS',
    driver_version='2.0.0,')
