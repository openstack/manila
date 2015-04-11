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

import doctest

import ddt
from lxml import doctestcompare
import mock
from oslo_log import log
from oslo_utils import units

import manila.db
from manila import exception
from manila.share import configuration as conf
from manila.share.drivers.emc import driver as emc_driver
from manila.share.drivers.emc.plugins.vnx import helper
from manila import test
from manila.tests import fake_share

LOG = log.getLogger(__name__)


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


class EMCVNXDriverTestData(object):
    emc_share_backend_default = 'vnx'
    emc_nas_server_container_default = 'server_2'
    emc_nas_pool_name_default = 'fakepool'
    emc_nas_server_default = '192.1.1.1'

    storage_pool_id_default = '48'

    FAKE_ERROR = ""
    FAKE_OUTPUT = ""
    GET_INTERCONNECT_ID = [
        'env', 'NAS_DB=/nas', '/nas/bin/nas_cel',
        '-interconnect', '-l',
    ]

    GET_INTERCONNECT_ID_OUT = (
        'id     name               source_server'
        '   destination_system   destination_server\n20001'
        '  loopback           server_2        nas149               server_2\n'
    )

    @staticmethod
    def copy_ckpt(share_name, src_share):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_copy',
            '-name', share_name + ':"fakepool"',
            '-source -ckpt', src_share,
            '-destination -fs', share_name,
            '-interconnect', 'id=20001',
            '-overwrite_destination',
            '-full_copy',
        ]

    COPY_CKPT_OUTPUT = "OK"

    @staticmethod
    def create_fs_from_ckpt(name, ckpt_name):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-name', name,
            '-type', 'uxfs',
            '-create',
            'samesize=' + ckpt_name,
            'pool="fakepool"',
            'storage=SINGLE',
            'worm=off',
            '-thin', 'no',
            '-option', 'slice=y',
        ]

    CREATE_FS_FROM_CKPT_OUT = 'id        = 515'

    @staticmethod
    def server_mount_cmd(vdm_name, share_name, mode):
        """The command to create server mount.

        :param mode: It should be 'ro' or 'rw'.
        """
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_mount', vdm_name,
            '-option', mode,
            share_name,
            '/' + share_name,
        ]

    @staticmethod
    def vdm_fake_out(vdm_name):
        return "%s : done" % vdm_name

    @staticmethod
    def nas_info_cmd(vdm_name):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-info', vdm_name,
        ]

    NAS_INFO_OUT = FAKE_OUTPUT

    @staticmethod
    def nas_info_out(share_name, ckpt):
        return ("""output = id        = 515
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
 disk=d7    fakeinfo""" % {'share_name': share_name, 'ckpt': ckpt})

    @staticmethod
    def server_umount_cmd(vdm_name, name):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_umount', vdm_name,
            '-perm', name,
        ]

    @staticmethod
    def fs_delete_cmd(vdm_name):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-delete', vdm_name,
            '-Force',
        ]

    @staticmethod
    def create_nfs_export(vdm_name, path):
        default_access = "rw=-*.*.*.*,root=-*.*.*.*,access=-*.*.*.*"
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', vdm_name,
            '-option', default_access,
            path,
        ]

    CREATE_NFS_EXPORT_OUT = "vdm_name : done"

    default_fs_id = 86
    default_vdm_id = 'vdm_id'
    default_vdm_name = 'vdm_name'
    default_mover_id = '1'
    default_mover_name = 'server_2'
    default_cifsserver_name = 'fakeserver2'

    @staticmethod
    def fake_share(**kwargs):
        return fake_share.fake_share(**kwargs)

    @staticmethod
    def fake_share_server(**kwargs):
        server = {
            'id': 'fake_server_id',
            'name': 'fake_server_name',
            'backend_details': {
                'share_server_name': TD.default_vdm_name,
                'share_server_id': TD.default_vdm_id,
                'nfs_if': '192.168.1.1',
                'cifs_if': '192.168.1.2',
            },
        }
        server.update(kwargs)
        return server

    @staticmethod
    def fake_snapshot(**kwargs):
        return fake_share.fake_snapshot(**kwargs)

    @staticmethod
    def fake_access(**kwargs):
        kwargs.update(access_to='10.0.0.2')
        return fake_share.fake_access(**kwargs)

    @staticmethod
    def fake_access_subnet(**kwargs):
        kwargs.update(access_to='10.0.0.2/24')
        return fake_share.fake_access(**kwargs)

    @staticmethod
    def fake_security_services(**kwargs):
        security_service = {
            'domain': 'win2012.openstack',
            'name': 'administrator',
            'user': 'administrator',
            'password': 'welcome',
            'dns_ip': '192.168.1.82',
            'type': 'active_directory',
        }
        security_service.update(kwargs)
        return [security_service]

    @staticmethod
    def fake_share_network(**kwargs):
        share_network = {
            'id': 'fakesharenetworkid',
            'segmentation_id': 'fakesegmentationid',
            'neutron_net_id': '111-222-333',
            'neutron_subnet_id': '111-222-333',
            'security_services': TD.fake_security_services(),
            'cidr': '192.168.1.0/24',
        }
        share_network.update(kwargs)
        return share_network

    @staticmethod
    def fake_network_info(**kwargs):
        share_server = TD.fake_share_server()
        share_network = TD.fake_share_network()

        network_allocations = [
            {
                'id': '111-222-333',
                'ip_address': '192.168.1.100',
            },
            {
                'id': '222-333-444',
                'ip_address': '192.168.1.101',
            }
        ]

        network_info = {
            'server_id': share_server['id'],
            'segmentation_id': share_network['segmentation_id'],
            'cidr': share_network['cidr'],
            'neutron_net_id': share_network['neutron_net_id'],
            'neutron_subnet_id': share_network['neutron_subnet_id'],
            'security_services': share_network['security_services'],
            'network_allocations': network_allocations,
            'backend_details': share_server['backend_details'],
        }
        network_info.update(kwargs)
        return network_info

    @staticmethod
    def fake_server_details(**kwargs):
        server_details = {
            'share_server_name': TD.default_vdm_name,
            'share_server_id': TD.default_vdm_id,
            'cifs_if': '192.168.1.100',
            'nfs_if': '192.168.1.101',
        }
        server_details.update(kwargs)
        return server_details

    @staticmethod
    @query
    def req_get_storage_pools():
        return '<StoragePoolQueryParams/>'

    @staticmethod
    @response
    def resp_get_storage_pools():
        return """<QueryStatus maxSeverity="ok"/>
        <StoragePool movers="" memberVolumes="" storageSystems="1"
            name="fakepool"
            description="Mapped Pool POOL_SAS1 on FNM00124500890"
            mayContainSlicesDefault="true" diskType="Performance"
            size="0" usedSize="0"
            autoSize="0" virtualProvisioning="true" isHomogeneous="true"
            dataServicePolicies="Thin=Yes,Compressed=No,Mirrored=No,Tiering
            policy=Auto-Tier/Optimize Pool" templatePool="48" stripeCount="5"
            stripeSize="256" pool="48">
            <SystemStoragePoolData dynamic="true"
                greedy="true" potentialAdditionalSize="0"
                size="839267" usedSize="77719"
                isBackendPool="true"/>
        </StoragePool>
        <StoragePool movers="1 2" memberVolumes="97"
            storageSystems="1" name="POOL_PERF" description=""
            mayContainSlicesDefault="true" diskType="Performance"
            size="51199" usedSize="1512"
            autoSize="51199" virtualProvisioning="true" isHomogeneous="true"
            dataServicePolicies="Thin=Yes,Compressed=No,Mirrored=No,
            Tiering policy=Auto-Tier/Optimize Pool" stripeCount="1"
            stripeSize="0" pool="49">
                <UserStoragePoolData/>
        </StoragePool>"""

    @staticmethod
    @query
    def req_get_mover():
        return (
            '<MoverQueryParams>'
            '<AspectSelection moverInterfaces="true" movers="true"/>'
            '</MoverQueryParams>'
        )

    @staticmethod
    @query
    def req_get_vdm_by_name():
        return '<VdmQueryParams/>'

    @staticmethod
    @response
    def resp_get_vdm_by_name():
        return """<QueryStatus maxSeverity="ok"/>
        <Vdm name="vdm-87e12630-c8f8-446c-abe7-364ba256b2cf"
         state="loaded" mover="1" rootFileSystem="394" vdm="55">
        <Status maxSeverity="ok"/>
        <Interfaces/>
        </Vdm>
        <Vdm name="%(vdm_name)s" state="loaded" mover="1"
         rootFileSystem="396" vdm="%(vdm_id)s">
        <Status maxSeverity="ok"/>
        <Interfaces>
        <li>if-9941bc3673a6</li>
        </Interfaces>
        </Vdm>""" % {'vdm_name': TD.default_vdm_name,
                     'vdm_id': TD.default_vdm_id}

    @staticmethod
    @response
    def resp_get_vdm_not_exist():
        return """<QueryStatus maxSeverity="ok"/>
        <Vdm name="vdm-1"
         state="loaded" mover="1" rootFileSystem="394" vdm="55">
        <Status maxSeverity="ok"/>
        <Interfaces/>
        </Vdm>
        <Vdm name="vdm-2" state="loaded" mover="1"
         rootFileSystem="396" vdm="54">
        <Status maxSeverity="ok"/>
        <Interfaces>
        <li>if-9941bc3673a6</li>
        </Interfaces>
        </Vdm>"""

    @staticmethod
    @response
    def resp_get_mover():
        return """<QueryStatus maxSeverity="ok"/>
        <Mover name="server_2" host="1" role="primary" standbys="2"
            i18NMode="UNICODE" failoverPolicy="auto"
            ntpServers="192.168.1.82" mover="1"/>
        <Mover name="server_3" host="2" role="standby" standbyFors="1"
            i18NMode="ASCII" failoverPolicy="none" mover="2"/>
        <MoverInterface name="el31" device="mge1" ipVersion="IPv4"
            netMask="255.255.255.0" broadcastAddr="128.221.253.255"
            macAddr="0:60:16:53:cc:86" mtu="1500" up="true" vlanid="0"
            mover="1" ipAddress="128.221.253.2"/>
        <MoverInterface name="interface-2-0" device="cge-2-0"
            ipVersion="IPv4"
            netMask="255.255.255.0" broadcastAddr="192.168.1.255"
            macAddr="0:60:48:1f:b9:94" mtu="1500" up="true" vlanid="0"
            mover="1" ipAddress="192.168.1.240"/>
        <MoverInterface name="el30" device="mge0" ipVersion="IPv4"
            netMask="255.255.255.0" broadcastAddr="128.221.252.255"
            macAddr="0:60:16:53:cc:9f" mtu="1500" up="true" vlanid="0"
            mover="2" ipAddress="128.221.252.3"/>"""

    @staticmethod
    @query
    def req_get_mover_ref():
        return (
            '<MoverQueryParams>'
            '<AspectSelection movers="true"/>'
            '</MoverQueryParams>'
        )

    @staticmethod
    @response
    def resp_get_mover_ref():
        return """<QueryStatus maxSeverity="ok"/>
        <Mover name="server_2" host="1" role="primary" standbys="2"
            i18NMode="UNICODE" failoverPolicy="auto"
            ntpServers="192.168.1.82" mover="1"/>
        <Mover name="server_3" host="2" role="standby" standbyFors="1"
            i18NMode="ASCII" failoverPolicy="none" mover="2"/>"""

    @staticmethod
    @query
    def req_get_mover_by_id():
        return (
            '<MoverQueryParams mover="%(mover_id)s">'
            '<AspectSelection moverInterfaces="true" moverStatuses="true" '
            'movers="true" moverNisDomains="true" moverNetworkDevices="true" '
            'moverDnsDomains="true" moverRoutes="true" '
            'moverDeduplicationSettings="true"/>'
            '</MoverQueryParams>'
            % {'mover_id': TD.default_mover_id}
        )

    @staticmethod
    @response
    def resp_get_mover_by_id():
        return (
            '<QueryStatus maxSeverity="ok"/><Mover name="%(mover_name)s" '
            'host="1" role="primary" i18NMode="UNICODE" failoverPolicy="none"'
            ' ntpServers="192.168.1.82" mover="%(mover_id)s"/>'
            '<MoverStatus version="T8.1.3.34944" csTime="1406795150" '
            'clock="140681" timezone="GMT-5" uptime="85096" '
            'mover="%(mover_id)s"><Status maxSeverity="ok"/>'
            '</MoverStatus>'
            '<MoverDnsDomain servers="192.168.1.82" protocol="udp" '
            'mover="%(mover_id)s" name="win2012.openstack"/>'
            '<MoverInterface name="el30" device="mge0" ipVersion="IPv4" '
            'netMask="255.255.255.0" broadcastAddr="128.221.252.255" '
            'macAddr="0:60:16:53:cc:87" mtu="1500" up="true" vlanid="0" '
            'mover="%(mover_id)s" ipAddress="128.221.252.2"/>'
            '<MoverRoute destination="0.0.0.0" interface="192.168.1.178" '
            'ipVersion="IPv4" netMask="0.0.0.0" '
            'gateway="192.168.1.217" mover="%(mover_id)s"/>'
            '<LogicalNetworkDevice speed="auto" interfaces="192.168.1.136" '
            'type="physical-ethernet" mover="%(mover_id)s" name="cge-2-0"/>'
            % {'mover_id': TD.default_mover_id,
               'mover_name': TD.default_mover_name}
        )

    @staticmethod
    @start_task
    def req_create_file_system(name='fakename', size=1):
        return (
            '<NewFileSystem name="%(name)s">'
            '<Vdm vdm="%(vdm_id)s"/><StoragePool mayContainSlices="true"'
            ' pool="%(pool)s" size="%(size)s"/>'
            '</NewFileSystem>'
            % {'vdm_id': TD.default_vdm_id,
               'name': name,
               'size': size * units.Ki,
               'pool': 48}
        )

    @staticmethod
    @start_task
    def req_create_file_system_on_vdm(name='fakename', size=1):
        return (
            '<NewFileSystem name="%(name)s">'
            '<Vdm vdm="%(id)s"/><StoragePool mayContainSlices="true" '
            'pool="%(pool)s" size="%(size)s"/>'
            '</NewFileSystem>'
            % {'name': name,
               'size': size * units.Ki,
               'pool': 48,
               'id': TD.default_vdm_id}
        )

    @staticmethod
    @response
    def resp_task_succeed():
        return (
            '<TaskResponse taskId="123">'
            '<Status maxSeverity="ok"/></TaskResponse>'
        )

    @staticmethod
    @start_task
    def req_create_nfs_share(name='fakename'):
        return (
            '<NewNfsExport mover="1" '
            'path="/%(name)s" readOnly="false">'
            '<AccessHosts><li>-*.*.*.*</li></AccessHosts><RwHosts><li>'
            '-*.*.*.*</li>'
            '</RwHosts><RootHosts><li>-*.*.*.*</li></RootHosts>'
            '</NewNfsExport>'
            % {'name': name}
        )

    @staticmethod
    @query
    def req_get_cifsservers(vdm_id):
        return (
            '<CifsServerQueryParams>'
            '<MoverOrVdm mover="%s" moverIdIsVdm="true"/>'
            '</CifsServerQueryParams>' % vdm_id
        )

    @staticmethod
    @response
    def resp_get_cifsservers():
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<CifsServer interfaces="192.168.1.2" type="W2K" '
            'localUsers="false" name="%(cifsserver)s" '
            'mover="%(mover_id)s" moverIdIsVdm="true"><Aliases>'
            '<li>1A6CD02419FC</li></Aliases><W2KServerData domain='
            '"WIN2012.OPENSTACK" compName="fakename" '
            'domainJoined="true"/></CifsServer>'
            % {'mover_id': TD.default_vdm_id,
               'cifsserver': TD.default_cifsserver_name}
        )

    @staticmethod
    @start_task
    def req_create_cifs_share(name='fakename',
                              servername=default_cifsserver_name):
        return (
            '<NewCifsShare path="/%(name)s" name="%(name)s">'
            '<MoverOrVdm mover="%(vdm_id)s" moverIdIsVdm="true"/>'
            '<CifsServers><li>%(servername)s</li>'
            '</CifsServers>'
            '</NewCifsShare>'
            % {'name': name,
               'vdm_id': TD.default_vdm_id,
               'servername': servername}
        )

    @staticmethod
    @start_task
    def req_delete_cifs_share(name='fakename'):
        return (
            '<DeleteCifsShare mover="%(moverid)s" moverIdIsVdm="true" '
            'name="%(name)s">'
            '<CifsServers><li>CIFS_SERVER</li></CifsServers>'
            '</DeleteCifsShare>'
            % {'name': name, 'moverid': TD.default_vdm_id}
        )

    @staticmethod
    @query
    def req_get_cifs_share_by_name(name='fakename'):
        return '<CifsShareQueryParams name="%(name)s"/>' % {'name': name}

    @staticmethod
    @response
    def resp_get_cifs_share_by_name(name='fakename'):
        return """<QueryStatus maxSeverity="ok"/>
        <CifsShare path="/%(name)s" fileSystem="%(fsid)s"
            name="%(name)s" mover="%(moverid)s" moverIdIsVdm="true">
            <CifsServers>
                <li>CIFS_SERVER</li>
            </CifsServers>
        </CifsShare>""" % {'fsid': TD.default_fs_id,
                           'name': name,
                           'moverid': TD.default_vdm_id}

    @staticmethod
    @response
    def resp_get_cifs_share_by_name_absence(name):
        return '<QueryStatus maxSeverity="ok"/>'

    @staticmethod
    @start_task
    def req_delete_mount(path='/fakename'):
        return (
            '<DeleteMount path="%(path)s" '
            'mover="%(moverid)s" moverIdIsVdm="true"/>'
            % {'path': path,
               'moverid': TD.default_vdm_id}
        )

    @staticmethod
    @query
    def req_get_filesystem(name='fakename', need_capacity=False):
        return (
            '<FileSystemQueryParams><AspectSelection '
            'fileSystemCapacityInfos="%(needcapacity)s" '
            'fileSystems="true"/>'
            '<Alias name="%(name)s"/>'
            '</FileSystemQueryParams>'
            % {'name': name,
               'needcapacity': 'true' if need_capacity else 'false'}
        )

    @staticmethod
    @response
    def resp_get_filesystem(name='fakename'):
        return """<QueryStatus maxSeverity="ok"/>
        <FileSystem name="%(name)s" type="uxfs" volume="236"
            storagePools="49" storages="1" containsSlices="true"
            internalUse="false" dataServicePolicies="Thin=Yes,
            Compressed=No,Mirrored=No,Tiering policy=Auto-Tier/Optimize Pool"
            fileSystem="%(fsid)s">
            <ProductionFileSystemData cwormState="off"/>
        </FileSystem>
        <FileSystemCapabilities fileSystem="86">
            <StoragePoolBased validPools="48 49 50" recommendedPool="49"/>
        </FileSystemCapabilities>
        <FileSystemCapacityInfo volumeSize="1024" fileSystem="86"/>""" \
               % {'fsid': TD.default_fs_id,
                  'name': name}

    @staticmethod
    @start_task
    def req_delete_filesystem(id):
        return '<DeleteFileSystem fileSystem="%s"/>' % id

    @staticmethod
    @query
    def req_query_check_point(name):
        return (
            '<CheckpointQueryParams><Alias name="%(name)s"/>'
            '</CheckpointQueryParams>'
            % {'name': name}
        )

    @staticmethod
    @response
    def resp_get_check_point(name):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<Checkpoint checkpointOf="148" name="%(name)s_replica1"'
            ' state="active" time="1405428355" fileSystemSize="0"'
            ' checkpoint="150"/>'
            % {'name': name}
        )

    @staticmethod
    @start_task
    def req_delete_check_point(point='150'):
        return '<DeleteCheckpoint checkpoint="%(point)s"/>' % {'point': point}

    @staticmethod
    @start_task
    def req_modify_file_system(name):
        return (
            '<ModifyFileSystem fileSystem="%(fsid)s"'
            ' newName="%(name)s"/>'
            % {'fsid': TD.default_fs_id,
               'name': name}
        )

    @staticmethod
    @query
    def req_query_mount():
        return (
            '<MountQueryParams><MoverOrVdm mover="1"/></MountQueryParams>'
        )

    @staticmethod
    @response
    def resp_mount_query(path='fake_path', fs_id='fake_id'):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<Mount fileSystem="%(fsID)s" disabled="false"'
            ' ntCredential="false" path="/%(path)s" mover="1"'
            ' moverIdIsVdm="false">'
            '<NfsOptions ro="false" virusScan="true"'
            ' prefetch="true" uncached="false"/>'
            '<CifsOptions cifsSyncwrite="false" notify="true"'
            ' triggerLevel="512" notifyOnAccess="false"'
            ' notifyOnWrite="false" oplock="true" accessPolicy="NATIVE"'
            ' lockingPolicy="nolock"/></Mount>'
            % {'path': path,
               'fsID': fs_id}
        )

    @staticmethod
    @start_task
    def req_create_mount_point(path='fakename'):
        return (
            '<NewMount fileSystem="%(fsid)s" path="/%(path)s">'
            '<MoverOrVdm mover="1"/></NewMount>'
            % {'fsid': TD.default_fs_id,
               'path': path}
        )

    @staticmethod
    def buildli(item):
        return '<li>%s</li>' % item

    @staticmethod
    @start_task
    def req_create_snapshot(fake_name='fakesnapshotname'):
        return (
            '<NewCheckpoint checkpointOf="%(fsid)s" '
            'name="%(fake_name)s"><SpaceAllocationMethod>'
            '<StoragePool pool="48"/></SpaceAllocationMethod>'
            '</NewCheckpoint>'
            % {'fsid': TD.default_fs_id,
               'fake_name': fake_name}
        )

    @staticmethod
    @start_task
    def req_delete_snapshot(snap_id='1'):
        return (
            '<DeleteCheckpoint checkpoint="%(id)s"/>'
            % {'id': snap_id}
        )

    @staticmethod
    @query
    def req_query_snapshot(fake_name='fakesnapshotname'):
        return (
            '<CheckpointQueryParams>'
            '<Alias name="%(fake_name)s"/>'
            '</CheckpointQueryParams>'
            % {'fake_name': fake_name}
        )

    @staticmethod
    @response
    def resp_query_snapshot(fake_name='fakesnapshotname'):
        return (
            '<QueryStatus maxSeverity="ok"/>'
            '<Checkpoint checkpointOf="%(fsid)s" '
            'name="%(fake_name)s" '
            'state="active" time="1405331413" '
            'fileSystemSize="0" checkpoint="1">'
            '<roFileSystemHosts mover="1" moverIdIsVdm="false"/>'
            '</Checkpoint>'
            % {'fsid': TD.default_fs_id,
               'fake_name': fake_name}
        )

    @staticmethod
    def resp_query_snapshot_error(fake_name='fakesnapshotname'):
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<ResponsePacket '
            'xmlns="http://www.emc.com/schemas/celerra/xml_api">'
            '<Response>'
            '<QueryStatus maxSeverity="ok"/>'
            '</Response>'
            '</ResponsePacket>'
            % {'fake_name': fake_name}
        )

    @staticmethod
    @response
    def resp_get_filesystem_error(fake_id='fakeid'):
        repeat_problem = (
            '<Problem messageCode="111" facility="Generic" component="API" '
            'message="fake error message." severity="warning">'
            '<Description>fake description.</Description>'
            '<Action>fake action to take.</Action>'
            '<Diagnostics>File system not found.</Diagnostics>'
            '</Problem>'
        )
        return (
            '<QueryStatus maxSeverity="warning">'
            + repeat_problem
            + repeat_problem
            + '</QueryStatus>'
        )

    @staticmethod
    @query
    def req_query_vdm():
        return '<VdmQueryParams/>'

    @staticmethod
    @response
    def resp_get_vdm(vdm_name='vdm_name', vdmID='10', IFName="fakeIF"):
        return (
            '<Vdm name="%(name)s" state="loaded" mover="1" '
            'rootFileSystem="431"'
            ' vdm="%(vdmID)s">'
            '<Status maxSeverity="ok"/><Interfaces><li>%(if_name)s</li>'
            '</Interfaces></Vdm>'
            '<Vdm name="vdm-fake" state="loaded" '
            'mover="1" rootFileSystem="438" vdm="72">'
            '<Status maxSeverity="ok"/>'
            '<Interfaces/></Vdm>'
            % {'name': vdm_name,
               'vdmID': vdmID,
               'if_name': IFName}
        )

    @staticmethod
    @response
    def resp_get_created_vdm():
        return (
            '<Vdm name="%(name)s" state="loaded" mover="1" '
            'rootFileSystem="431"'
            ' vdm="%(vdm_id)s">'
            '<Status maxSeverity="ok"/><Interfaces>'
            '</Interfaces>'
            '</Vdm>'
            % {'name': 'vdm-' + TD.fake_share_server()['id'],
               'vdm_id': TD.default_vdm_id}
        )

    @staticmethod
    def req_get_nfs_share_by_path(mover_name, path):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-P', 'nfs',
            '-list', path,
        ]

    @staticmethod
    def resp_get_nfs_share_by_path(mover_name, path, hosts=[]):
        hosts = ["-*.*.*.*"] + hosts
        return (
            '%(mover_name)s :\nexport "%(path)s" '
            'rw=%(host)s root=%(host)s '
            'access=%(host)s\n'
            % {'mover_name': mover_name,
               'path': path,
               'host': ":".join(hosts)}
        )

    @staticmethod
    def resp_get_nfs_share_by_path_path_unexist(mover_name):
        return (
            '%(mover_name)s : Error 2: %(mover_name)s : No such file '
            'or directory\n'
            % {'mover_name': mover_name}
        )

    @staticmethod
    def resp_get_nfs_share_by_path_vdm_unexist():
        return 'vdm-fake :\nError 4023: vdm-fake : unknown host'

    @staticmethod
    def resp_get_nfs_share_by_path_absence(mover_name):
        return '%(mover_name) :\n error' % mover_name

    @staticmethod
    def req_delete_nfs_share(path, mover_name):
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-unexport',
            '-perm',
            path,
        ]

    @staticmethod
    def resp_delete_nfs_share_success(mover_name):
        return "%s : done" % mover_name

    @staticmethod
    def req_set_nfs_share_access(path, mover_name, hosts=[]):
        hosts = ["-*.*.*.*"] + hosts
        access_str = ("rw=%(host)s,root=%(host)s,access=%(host)s"
                      % {'host': ":".join(hosts)})
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-ignore',
            '-option', access_str,
            path,
        ]

    @staticmethod
    def resp_change_nfs_share_success(mover_name):
        return "%s : done" % mover_name

    @staticmethod
    def resp_allow_cifs_access(access):
        cifs_share = TD.fake_share(share_proto='CIFS')
        domain = TD.fake_security_services()[0]['domain']
        user = access['access_to']
        return (
            "Command succeeded:  :3 sharesd %(share)s grant             "
            "%(user)s@%(domain)s=fullcontrol"
            % {'share': cifs_share['name'],
               'user': user,
               'domain': domain}
        )

    @staticmethod
    def req_allow_deny_cifs_access(access, action='grant'):
        cifs_share = TD.fake_share(share_proto='CIFS')
        domain = TD.fake_security_services()[0]['domain']
        user = access['access_to']
        account = user + '@' + domain
        allow_str = (
            'sharesd %(share_name)s %(action)s %(account)s=%(access)s'
            % {'share_name': cifs_share['name'],
               'action': action,
               'account': account,
               'access': 'fullcontrol'}
        )
        return [
            'env', 'NAS_DB=/nas',
            '/nas/bin/.server_config', TD.default_vdm_name,
            '-v', '"%s"' % allow_str,
        ]

    @staticmethod
    def req_disable_cifs_access():
        share_name = TD.fake_share(share_proto='CIFS')['name']
        cmd_str = 'sharesd %s set noaccess' % share_name
        return [
            'env', 'NAS_DB=/nas',
            '/nas/bin/.server_config', TD.default_vdm_name,
            '-v', '"%s"' % cmd_str,
        ]

    @staticmethod
    @start_task
    def req_create_vdm():
        return (
            '<NewVdm mover="1" name="%s"/>'
            % ('vdm-' + TD.fake_share_server()['id'])
        )

    @staticmethod
    @start_task
    def req_create_mover_interface(if_name, ip_addr):
        return (
            '<NewMoverInterface name="%(if_name)s" vlanid="%(vlan)s" '
            'netMask="255.255.255.0" device="cge-2-0" '
            'mover="1" ipAddress="%(ip)s"/>'
            % {'if_name': if_name,
               'vlan': TD.fake_share_network()['segmentation_id'],
               'ip': ip_addr}
        )

    @staticmethod
    @start_task
    def req_create_dns_domain():
        return (
            '<NewMoverDnsDomain mover="%s" protocol="udp" '
            'name="win2012.openstack" servers="192.168.1.82"/>'
            % TD.default_mover_id
        )

    @staticmethod
    @start_task
    def req_create_cifs_server(ip):
        vdm_name = 'vdm-' + TD.fake_share_server()['id']
        return (
            '<NewW2KCifsServer interfaces="%(ip)s" compName="%(vdm_name)s" '
            'name="%(name)s" domain="win2012.openstack">'
            '<MoverOrVdm mover="%(vdm_id)s" moverIdIsVdm="true"/>'
            '<Aliases><li>%(alias)s</li></Aliases>'
            '<JoinDomain userName="administrator" password="welcome"/>'
            '</NewW2KCifsServer>'
            % {'ip': ip,
               'vdm_name': vdm_name,
               'name': vdm_name[-14:],
               'vdm_id': TD.default_vdm_id,
               'alias': vdm_name[-12:]}
        )

    @staticmethod
    def req_enable_nfs_service(if_name):
        vdm_name = 'vdm-' + TD.fake_share_server()['id']
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-vdm', vdm_name,
            '-attach', if_name,
        ]

    @staticmethod
    def req_disable_nfs_service(if_name):
        vdm_name = TD.default_vdm_name
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-vdm', vdm_name,
            '-detach', if_name,
        ]

    @staticmethod
    def resp_disable_nfs_service_success():
        return """id        = %(vdmid)s
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
 interface=if-123232334343 :cifs""" % {'vdmid': TD.default_vdm_id,
                                       'name': TD.default_vdm_name}

    @staticmethod
    def req_get_interfaces_by_vdm():
        vdm_name = TD.default_vdm_name
        return [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-i',
            '-vdm', vdm_name,
        ]

    @staticmethod
    def resp_get_interfaces_by_vdm():
        return """id        = %(vdmid)s
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
 interface=if-4e680a36d8bd :vdm
 interface=if-123232334343 :cifs""" % {'vdmid': TD.default_vdm_id,
                                       'name': TD.default_vdm_name}

    @staticmethod
    @start_task
    def req_modify_cifs_server():
        return (
            '<ModifyW2KCifsServer mover="%(vdmid)s" moverIdIsVdm="true" '
            'name="%(cifsserver)s">'
            '<DomainSetting userName="%(username)s" password="%(pw)s" '
            'joinDomain="false"/>'
            '</ModifyW2KCifsServer>'
            % {'vdmid': TD.default_vdm_id,
               'cifsserver': TD.default_cifsserver_name,
               'username': TD.fake_security_services()[0]['user'],
               'pw': TD.fake_security_services()[0]['password']}
        )

    @staticmethod
    @start_task
    def req_delete_cifs_server():
        return (
            '<DeleteCifsServer mover="%(vdmid)s" moverIdIsVdm="true" '
            'name="%(cifsserver)s"/>'
            % {'vdmid': TD.default_vdm_id,
               'cifsserver': TD.default_cifsserver_name}
        )

    @staticmethod
    @start_task
    def delete_mover_interface(ip):
        return (
            '<DeleteMoverInterface mover="1" ipAddress="%(ipaddr)s"/>'
            % {'ipaddr': ip}
        )

    @staticmethod
    @start_task
    def delete_vdm(id):
        return '<DeleteVdm vdm="%(vdmid)s"/>' % {'vdmid': id}


TD = EMCVNXDriverTestData
CHECKER = doctestcompare.LXMLOutputChecker()
PARSE_XML = doctest.register_optionflag('PARSE_XML')


class RequestSideEffect(object):
    def __init__(self):
        self.actions = []
        self.started = False

    def append(self, resp=None, ex=None):
        if not self.started:
            self.actions.append((resp, ex))

    def __call__(self, *args, **kwargs):
        if not self.started:
            self.started = True
            self.actions.reverse()
        item = self.actions.pop()
        if item[1]:
            raise item[1]
        else:
            return item[0]


class SSHSideEffect(object):
    def __init__(self):
        self.actions = []
        self.started = False

    def append(self, resp=None, err=None, ex=None):
        if not self.started:
            self.actions.append((resp, err, ex))

    def __call__(self, rel_url, req_data=None, method=None,
                 return_rest_err=True, *args, **kwargs):
        if not self.started:
            self.started = True
            self.actions.reverse()
        item = self.actions.pop()
        if item[2]:
            raise item[2]
        else:
            if return_rest_err:
                return item[0:2]
            else:
                return item[1]


class EMCMock(mock.Mock):
    def _get_req_from_call(self, call):
        if len(call) == 3:
            return call[1][0]
        elif len(call) == 2:
            return call[0][0]

    def assert_has_calls(self, calls):
        if len(calls) != len(self.mock_calls):
            raise AssertionError(
                'Mismatch error.\nExpected: %r\n'
                'Actual: %r' % (calls, self.mock_calls)
            )

        iter_expect = iter(calls)
        iter_actual = iter(self.mock_calls)

        while True:
            try:
                expect = self._get_req_from_call(iter_expect.next())
                actual = self._get_req_from_call(iter_actual.next())
            except StopIteration:
                return True

            if not CHECKER.check_output(expect, actual, PARSE_XML):
                raise AssertionError(
                    'Mismatch error.\nExpected: %r\n'
                    'Actual: %r' % (calls, self.mock_calls)
                )


@ddt.ddt
class EMCShareDriverVNXTestCase(test.TestCase):
    def setUp(self):
        super(EMCShareDriverVNXTestCase, self).setUp()
        self.configuration = conf.Configuration(None)
        self.configuration.append_config_values = mock.Mock(return_value=0)
        self.configuration.emc_share_backend = TD.emc_share_backend_default
        self.configuration.emc_nas_server_container = (
            TD.emc_nas_server_container_default)
        self.configuration.emc_nas_pool_name = TD.emc_nas_pool_name_default
        self.configuration.emc_nas_login = 'fakename'
        self.configuration.emc_nas_password = 'fakepwd'
        self.configuration.emc_nas_server = TD.emc_nas_server_default
        self.configuration.share_backend_name = 'fake_backend'
        self.mock_object(self.configuration, 'safe_get', self._fake_safe_get)
        self.driver = emc_driver.EMCShareDriver(
            configuration=self.configuration)
        self.driver_setup()

    def driver_setup(self):
        hook = RequestSideEffect()
        hook.append(TD.resp_get_mover_ref())
        hook.append(TD.resp_get_storage_pools())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        helper.XMLAPIConnector.do_setup = EMCMock()
        self.driver.do_setup(None)
        expected_calls = [
            mock.call(TD.req_get_mover_ref()),
            mock.call(TD.req_get_storage_pools()),
        ]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)
        helper.XMLAPIConnector.do_setup.assert_called_once_with()
        pool_id = self.driver.plugin._pool['id']
        self.assertEqual(pool_id, TD.storage_pool_id_default,
                         "Storage pool id parse error")

    def test_setup_server(self):
        hook = RequestSideEffect()
        ssh_hook = SSHSideEffect()
        network_info = TD.fake_network_info()
        if_data1 = network_info['network_allocations'][0]
        if_data2 = network_info['network_allocations'][1]
        if_name1 = 'if-' + if_data1['id'][-12:]
        if_ip1 = if_data1['ip_address']
        if_name2 = 'if-' + if_data2['id'][-12:]
        if_ip2 = if_data2['ip_address']
        hook.append(TD.resp_get_mover_ref())
        hook.append(TD.resp_get_vdm_not_exist())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_get_created_vdm())
        hook.append(TD.resp_get_mover_by_id())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_get_mover_ref())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_task_succeed())
        ssh_hook.append('', '')
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=ssh_hook)
        self.driver.setup_server(network_info, None)
        expected_calls = [
            mock.call(TD.req_get_mover_ref()),
            mock.call(TD.req_get_vdm_by_name()),
            mock.call(TD.req_create_vdm()),
            mock.call(TD.req_get_vdm_by_name()),
            mock.call(TD.req_get_mover_by_id()),
            mock.call(TD.req_create_mover_interface(if_name1, if_ip1)),
            mock.call(TD.req_create_mover_interface(if_name2, if_ip2)),
            mock.call(TD.req_get_mover_ref()),
            mock.call(TD.req_create_dns_domain()),
            mock.call(TD.req_create_cifs_server(if_ip1)),
        ]
        ssh_calls = [mock.call(TD.req_enable_nfs_service(if_name2))]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)
        helper.SSHConnector.run_ssh.assert_has_calls(ssh_calls)

    def test_teardown_server(self):
        security_services = TD.fake_security_services()
        server_details = TD.fake_server_details()
        hook = RequestSideEffect()
        hook.append(TD.resp_get_vdm_by_name())
        hook.append(TD.resp_get_cifsservers())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_task_succeed())

        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)

        ssh_hook = SSHSideEffect()
        ssh_hook.append(TD.resp_get_interfaces_by_vdm())
        ssh_hook.append(TD.resp_disable_nfs_service_success())
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=ssh_hook)

        self.driver.teardown_server(server_details, security_services)
        expected_calls = [
            mock.call(TD.req_get_vdm_by_name()),
            mock.call(TD.req_get_cifsservers(TD.default_vdm_id)),
            mock.call(TD.req_modify_cifs_server()),
            mock.call(TD.req_delete_cifs_server()),
            mock.call(TD.delete_mover_interface(server_details['cifs_if'])),
            mock.call(TD.delete_mover_interface(server_details['nfs_if'])),
            mock.call(TD.delete_vdm(TD.default_vdm_id)),
        ]
        ssh_calls = [
            mock.call(TD.req_get_interfaces_by_vdm()),
            mock.call(TD.req_disable_nfs_service("if-4e680a36d8bd ")),
        ]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)
        helper.SSHConnector.run_ssh.assert_has_calls(ssh_calls)

    @ddt.data(fake_share.fake_share(),
              fake_share.fake_share(share_proto='NFSBOGUS'),
              fake_share.fake_share(share_proto='CIFSBOGUS'))
    def test_create_share_with_wrong_proto(self, share):
        share_server = TD.fake_share_server()
        hook = RequestSideEffect()
        hook.append(TD.resp_get_vdm())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_task_succeed())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        sshHook = SSHSideEffect()
        sshHook.append(TD.CREATE_NFS_EXPORT_OUT, TD.FAKE_ERROR)
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share, None, share, share_server)

    def test_create_nfs_share_default(self):
        share = TD.fake_share(share_proto='NFS')
        share_server = TD.fake_share_server()
        vdm_name = share_server['backend_details']['share_server_name']
        hook = RequestSideEffect()
        hook.append(TD.resp_get_vdm())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_task_succeed())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        sshHook = SSHSideEffect()
        sshHook.append(TD.CREATE_NFS_EXPORT_OUT, TD.FAKE_ERROR)
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        location = self.driver.create_share(None, share, share_server)
        expected_calls = [
            mock.call(TD.req_create_file_system_on_vdm(share['name'])),
        ]

        ssh_calls = [mock.call(TD.create_nfs_export(vdm_name, '/fakename'))]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)
        helper.SSHConnector.run_ssh.assert_has_calls(ssh_calls)
        self.assertEqual(location, '192.168.1.1:/%s' % share['name'],
                         "NFS export path is incorrect")

    @ddt.data(fake_share.fake_share(),
              fake_share.fake_share(share_proto='NFSBOGUS'),
              fake_share.fake_share(share_proto='CIFSBOGUS'))
    def test_delete_share_with_wrong_proto(self, share):
        share_server = TD.fake_share_server()
        mover_name = share_server['backend_details']['share_server_name']
        path = '/' + share['name']
        sshHook = SSHSideEffect()
        sshHook.append(TD.resp_get_nfs_share_by_path(mover_name,
                                                     path))
        sshHook.append(TD.resp_delete_nfs_share_success(mover_name))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)

        hook = RequestSideEffect()
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_get_filesystem(share['name']))
        hook.append(TD.resp_task_succeed())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        self.assertRaises(exception.InvalidShare,
                          self.driver.delete_share,
                          None, share, share_server)

    def test_delete_nfs_share_default(self):
        share = TD.fake_share(share_proto='NFS')
        share_server = TD.fake_share_server()
        mover_name = share_server['backend_details']['share_server_name']
        path = '/' + share['name']
        sshHook = SSHSideEffect()
        sshHook.append(TD.resp_get_nfs_share_by_path(mover_name,
                                                     path))
        sshHook.append(TD.resp_delete_nfs_share_success(mover_name))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)

        hook = RequestSideEffect()
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_get_filesystem(share['name']))
        hook.append(TD.resp_task_succeed())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        self.driver.delete_share(None, share, share_server)
        expected_calls = [
            mock.call(TD.req_get_nfs_share_by_path(mover_name, path)),
            mock.call(TD.req_delete_nfs_share(path, mover_name)),
        ]
        helper.SSHConnector.run_ssh.assert_has_calls(expected_calls)

        expected_calls = [
            mock.call(TD.req_delete_mount(path)),
            mock.call(TD.req_get_filesystem(share['name'],
                                            need_capacity=True)),
            mock.call(TD.req_delete_filesystem(TD.default_fs_id)),
        ]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)

    def test_delete_nfs_share_but_share_absent(self):
        share = TD.fake_share(share_proto='NFS')
        share_server = TD.fake_share_server()
        mover_name = share_server['backend_details']['share_server_name']
        path = '/' + share['name']
        sshHook = SSHSideEffect()
        sshHook.append(TD.resp_get_nfs_share_by_path_path_unexist(mover_name))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)

        hook = RequestSideEffect()
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_get_filesystem(share['name']))
        hook.append(TD.resp_task_succeed())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        self.driver.delete_share(None, share, share_server)
        expected_calls = [
            mock.call(TD.req_get_nfs_share_by_path(mover_name, path)),
        ]
        helper.SSHConnector.run_ssh.assert_has_calls(expected_calls)

        expected_calls = [
            mock.call(TD.req_delete_mount(path)),
            mock.call(TD.req_get_filesystem(share['name'],
                                            need_capacity=True)),
            mock.call(TD.req_delete_filesystem(TD.default_fs_id)),
        ]

        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)

    def test_create_cifs_share_default(self):
        share = TD.fake_share(share_proto='CIFS')
        hook = RequestSideEffect()
        ssh_hook = SSHSideEffect()
        share_server = TD.fake_share_server()
        vdm_id = share_server['backend_details']['share_server_id']
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_get_cifsservers())
        hook.append(TD.resp_task_succeed())

        ssh_hook.append('Command succeeded')
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=ssh_hook)
        location = self.driver.create_share(None, share, share_server)
        ssh_calls = [mock.call(TD.req_disable_cifs_access())]
        expected_calls = [
            mock.call(TD.req_create_file_system(share['name'])),
            mock.call(TD.req_get_cifsservers(vdm_id)),
            mock.call(TD.req_create_cifs_share(share['name'],
                                               TD.default_cifsserver_name)),
        ]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)
        helper.SSHConnector.run_ssh.assert_has_calls(ssh_calls)
        self.assertEqual(location, '\\\\192.168.1.2\\%s' % share['name'],
                         "CIFS export path is incorrect")

    def test_delete_cifs_share_default(self):
        share = TD.fake_share(share_proto='CIFS')
        share_server = TD.fake_share_server()
        hook = RequestSideEffect()
        hook.append(TD.resp_get_cifs_share_by_name(share['name']))
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_get_filesystem(share['name']))
        hook.append(TD.resp_task_succeed())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        self.driver.delete_share(
            None, TD.fake_share(share_proto='CIFS'), share_server)
        expected_calls = [
            mock.call(TD.req_get_cifs_share_by_name(share['name'])),
            mock.call(TD.req_delete_cifs_share(share['name'])),
            mock.call(TD.req_delete_mount('/' + share['name'])),
            mock.call(TD.req_get_filesystem(share['name'],
                                            need_capacity=True)),
            mock.call(TD.req_delete_filesystem(TD.default_fs_id)),
        ]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)

    def test_delete_cifs_share_but_share_absent(self):
        share = TD.fake_share(share_proto='CIFS')
        share_server = TD.fake_share_server()
        hook = RequestSideEffect()
        hook.append(TD.resp_get_cifs_share_by_name_absence(share['name']))
        hook.append(TD.resp_task_succeed())
        hook.append(TD.resp_get_filesystem(share['name']))
        hook.append(TD.resp_task_succeed())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        self.driver.delete_share(
            None, TD.fake_share(share_proto='CIFS'), share_server)
        expected_calls = [
            mock.call(TD.req_get_cifs_share_by_name(share['name'])),
            mock.call(TD.req_delete_mount('/' + share['name'])),
            mock.call(TD.req_get_filesystem(share['name'],
                                            need_capacity=True)),
            mock.call(TD.req_delete_filesystem(TD.default_fs_id)),
        ]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)

    def test_create_snapshot(self):
        snap = TD.fake_snapshot()
        hook = RequestSideEffect()
        hook.append(TD.resp_get_filesystem(snap['share_name']))
        hook.append(TD.resp_task_succeed())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        self.driver.create_snapshot(None, snap)
        expected_calls = [
            mock.call(TD.req_get_filesystem(snap['share_name'],
                                            need_capacity=True)),
            mock.call(TD.req_create_snapshot(snap['name'])),
        ]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)

    def test_create_snapshot_error(self):
        snap = TD.fake_snapshot()
        hook = RequestSideEffect()
        hook.append(TD.resp_get_filesystem_error())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        self.assertRaises(exception.EMCVnxXMLAPIError,
                          self.driver.create_snapshot,
                          None,
                          TD.fake_snapshot())
        expected_calls = [
            mock.call(TD.req_get_filesystem(snap['share_name'],
                                            need_capacity=True)),
        ]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)

    def test_delete_snapshot(self):
        snap = TD.fake_snapshot()
        hook = RequestSideEffect()
        hook.append(TD.resp_query_snapshot())
        hook.append(TD.resp_task_succeed())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        self.driver.delete_snapshot(None, snap)
        expected_calls = [
            mock.call(TD.req_query_snapshot(snap['name'])),
            mock.call(TD.req_delete_snapshot('1')),
        ]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)

    def test_delete_snapshot_not_exist(self):
        hook = RequestSideEffect()
        hook.append(TD.resp_query_snapshot_error())
        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        self.driver.delete_snapshot(None, TD.fake_snapshot())
        expected_calls = [mock.call(TD.req_query_snapshot('fakesnapshotname'))]
        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)

    @ddt.data(fake_share.fake_share(),
              fake_share.fake_share(share_proto='NFSBOGUS'),
              fake_share.fake_share(share_proto='CIFSBOGUS'))
    def test_allow_access_with_wrong_proto(self, share):
        access = fake_share.fake_access()
        share_server = TD.fake_share_server()
        mover_name = share_server['backend_details']['share_server_name']
        path = '/' + share['name']
        sshHook = SSHSideEffect()
        sshHook.append(TD.resp_get_nfs_share_by_path(mover_name,
                                                     path))
        sshHook.append(TD.resp_change_nfs_share_success(mover_name))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        self.assertRaises(exception.InvalidShare,
                          self.driver.allow_access,
                          None, share, access, share_server)

    def test_nfs_allow_access(self):
        share = TD.fake_share(share_proto='NFS')
        access = TD.fake_access()
        share_server = TD.fake_share_server()
        mover_name = share_server['backend_details']['share_server_name']
        path = '/' + share['name']
        sshHook = SSHSideEffect()
        sshHook.append(TD.resp_get_nfs_share_by_path(mover_name,
                                                     path))
        sshHook.append(TD.resp_change_nfs_share_success(mover_name))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        self.driver.allow_access(None, share, access, share_server)
        expected_calls = [
            mock.call(TD.req_get_nfs_share_by_path(mover_name, path)),
            mock.call(TD.req_set_nfs_share_access(
                path,
                mover_name,
                [access['access_to']])),
        ]
        helper.SSHConnector.run_ssh.assert_has_calls(expected_calls)

    def test_nfs_allow_access_subnet(self):
        share = TD.fake_share(share_proto='NFS')
        access = TD.fake_access_subnet()
        share_server = TD.fake_share_server()
        mover_name = share_server['backend_details']['share_server_name']
        path = '/' + share['name']
        sshHook = SSHSideEffect()
        sshHook.append(TD.resp_get_nfs_share_by_path(mover_name,
                                                     path))
        sshHook.append(TD.resp_change_nfs_share_success(mover_name))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        self.driver.allow_access(None, share, access, share_server)
        expected_calls = [
            mock.call(TD.req_get_nfs_share_by_path(mover_name, path)),
            mock.call(TD.req_set_nfs_share_access(
                path,
                mover_name,
                [access['access_to']])),
        ]
        helper.SSHConnector.run_ssh.assert_has_calls(expected_calls)

    def test_nfs_deny_access_subnet(self):
        share = TD.fake_share(share_proto='NFS')
        access = TD.fake_access_subnet()
        share_server = TD.fake_share_server()
        mover_name = share_server['backend_details']['share_server_name']
        path = '/' + share['name']
        sshHook = SSHSideEffect()
        sshHook.append(TD.resp_get_nfs_share_by_path(
            mover_name,
            path,
            [access['access_to']]))

        sshHook.append(TD.resp_change_nfs_share_success(mover_name))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        self.driver.deny_access(None, share, access, share_server)
        expected_calls = [
            mock.call(TD.req_get_nfs_share_by_path(mover_name, path)),
            mock.call(TD.req_set_nfs_share_access(path, mover_name, [])),
        ]
        helper.SSHConnector.run_ssh.assert_has_calls(expected_calls)

    @ddt.data(fake_share.fake_share(),
              fake_share.fake_share(share_proto='NFSBOGUS'),
              fake_share.fake_share(share_proto='CIFSBOGUS'))
    def test_deny_access_with_wrong_proto(self, share):
        access = fake_share.fake_access()
        share_server = TD.fake_share_server()
        mover_name = share_server['backend_details']['share_server_name']
        path = '/' + share['name']
        sshHook = SSHSideEffect()
        sshHook.append(TD.resp_get_nfs_share_by_path(mover_name,
                                                     path,
                                                     [access['access_to']]))
        sshHook.append(TD.resp_change_nfs_share_success(mover_name))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        self.assertRaises(exception.InvalidShare,
                          self.driver.deny_access,
                          None, share, access, share_server)

    def test_nfs_deny_access(self):
        share = TD.fake_share(share_proto='NFS')
        access = TD.fake_access()
        share_server = TD.fake_share_server()
        mover_name = share_server['backend_details']['share_server_name']
        path = '/' + share['name']
        sshHook = SSHSideEffect()
        sshHook.append(TD.resp_get_nfs_share_by_path(mover_name,
                                                     path,
                                                     [access['access_to']]))
        sshHook.append(TD.resp_change_nfs_share_success(mover_name))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        self.driver.deny_access(None, share, access, share_server)
        expected_calls = [
            mock.call(TD.req_get_nfs_share_by_path(mover_name, path)),
            mock.call(TD.req_set_nfs_share_access(path, mover_name, [])),
        ]
        helper.SSHConnector.run_ssh.assert_has_calls(expected_calls)

    @mock.patch('manila.db.share_network_get',
                mock.Mock(return_value=TD.fake_share_network()))
    def test_cifs_allow_access(self):
        context = 'fake_context'
        share = TD.fake_share(share_proto='CIFS')
        access = TD.fake_access(**{'access_type': 'user',
                                   'access_to': 'administrator'})
        share_server = TD.fake_share_server()
        ssh_hook = SSHSideEffect()
        ssh_hook.append(TD.resp_allow_cifs_access(access))
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=ssh_hook)
        self.driver.allow_access(context, share, access, share_server)
        expected_calls = [mock.call(TD.req_allow_deny_cifs_access(access))]
        helper.SSHConnector.run_ssh.assert_has_calls(expected_calls)
        manila.db.share_network_get.assert_called_once_with(
            context, share['share_network_id'])

    @mock.patch('manila.db.share_network_get',
                mock.Mock(return_value=TD.fake_share_network()))
    def test_cifs_deny_access(self):
        context = 'fake_context'
        share = TD.fake_share(share_proto='CIFS')
        access = TD.fake_access(**{'access_type': 'user',
                                   'access_to': 'administrator'})
        share_server = TD.fake_share_server()
        ssh_hook = SSHSideEffect()
        ssh_hook.append('Command succeeded')
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=ssh_hook)
        self.driver.deny_access(context, share, access, share_server)
        expected_calls = [
            mock.call(TD.req_allow_deny_cifs_access(access, 'revoke')),
        ]
        helper.SSHConnector.run_ssh.assert_has_calls(expected_calls)
        manila.db.share_network_get.assert_called_once_with(
            context, share['share_network_id'])

    @ddt.data(fake_share.fake_share(),
              fake_share.fake_share(share_proto='NFSBOGUS'),
              fake_share.fake_share(share_proto='CIFSBOGUS'))
    def test_create_share_from_snapshot_with_wrong_proto(self, share):
        snap = fake_share.fake_snapshot()
        share_server = TD.fake_share_server()
        fake_ckpt = "fake_ckpt"
        hook = RequestSideEffect()
        hook.append(TD.resp_get_filesystem(share['name']))

        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        sshHook = SSHSideEffect()
        sshHook.append(TD.GET_INTERCONNECT_ID_OUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.COPY_CKPT_OUTPUT)
        sshHook.append(TD.nas_info_out(snap['name'], fake_ckpt), TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.CREATE_NFS_EXPORT_OUT, TD.FAKE_ERROR)
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        self.assertRaises(exception.InvalidShare,
                          self.driver.create_share_from_snapshot,
                          None, share, snap, share_server)

    def test_create_share_from_snapshot(self):
        share = TD.fake_share(share_proto='NFS')
        snap = TD.fake_snapshot()
        share_server = TD.fake_share_server()
        fake_ckpt = "fake_ckpt"
        vdm_name = share_server['backend_details']['share_server_name']
        hook = RequestSideEffect()
        hook.append(TD.resp_get_filesystem(share['name']))

        helper.XMLAPIConnector.request = EMCMock(side_effect=hook)
        sshHook = SSHSideEffect()
        sshHook.append(TD.GET_INTERCONNECT_ID_OUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.COPY_CKPT_OUTPUT)
        sshHook.append(TD.nas_info_out(snap['name'], fake_ckpt), TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.FAKE_OUTPUT, TD.FAKE_ERROR)
        sshHook.append(TD.CREATE_NFS_EXPORT_OUT, TD.FAKE_ERROR)
        helper.SSHConnector.run_ssh = mock.Mock(side_effect=sshHook)
        self.driver.create_share_from_snapshot(None,
                                               share,
                                               snap,
                                               share_server)
        expected_calls = [
            mock.call(TD.req_get_filesystem(share['name'],
                                            need_capacity=True)),
        ]

        ssh_calls = [
            mock.call(TD.GET_INTERCONNECT_ID),
            mock.call(TD.create_fs_from_ckpt(snap['share_name'],
                                             share['name'])),
            mock.call(TD.server_mount_cmd(vdm_name,
                                          snap['share_name'], 'ro')),
            mock.call(TD.copy_ckpt(snap['share_name'], snap['name'])),
            mock.call(TD.nas_info_cmd(snap['share_name'])),
            mock.call(TD.server_umount_cmd(vdm_name, fake_ckpt)),
            mock.call(TD.fs_delete_cmd(fake_ckpt)),
            mock.call(TD.server_mount_cmd(vdm_name,
                                          snap['share_name'], 'rw')),
            mock.call(TD.create_nfs_export(vdm_name,
                                           '/' + snap['share_name'])),
        ]

        helper.XMLAPIConnector.request.assert_has_calls(expected_calls)
        helper.SSHConnector.run_ssh.assert_has_calls(ssh_calls)

    def _fake_safe_get(self, value):
        if value == "emc_share_backend":
            return "vnx"
        elif value == 'driver_handles_share_servers':
            return True
        return None
