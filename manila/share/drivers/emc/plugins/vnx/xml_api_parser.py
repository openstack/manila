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
import types
import xml.dom.minidom

from manila.openstack.common import log


LOG = log.getLogger(__name__)


def name(tt):
    return tt[0]


def attrs(tt):
    return tt[1]


def kids(tt):
    return filter_tuples(tt[2])


def filter_tuples(l):
    """Return only the tuples in a list.

    In a tupletree, tuples correspond to XML elements.  Useful for
    stripping out whitespace data in a child list.
    """

    if l is None:
        return []
    else:
        return [x for x in l if type(x) == tuple]


def parse_xml_api(tt):
    check_node(tt, 'ResponsePacket', ['xmlns'])

    child = optional_child(tt, ['Response', 'PacketFault'])

    return child


def parse_response(tt):
    check_node(tt, 'Response')

    list_child = [
        'QueryStatus',
        'FileSystem',
        'FileSystemCapabilities',
        'FileSystemCapacityInfo',
        'Mount',
        'CifsShare',
        'CifsServer',
        'Volume',
        'StoragePool',
        'Fault',
        'TaskResponse',
        'Checkpoint',
        'NfsExport',
        'Mover',
        'MoverStatus',
        'MoverDnsDomain',
        'MoverInterface',
        'MoverRoute',
        'LogicalNetworkDevice',
        'MoverDeduplicationSettings',
        'Vdm',
    ]
    return list_of_various(tt, list_child)


def parse_querystatus(tt):
    check_node(tt, 'QueryStatus', ['maxSeverity'])

    child = list_of_various(tt, ['Problem'])

    if child:
        return name(tt), attrs(tt), child
    else:
        return name(tt), attrs(tt)


def parse_filesystem(tt):
    required_attrs = ['fileSystem', 'name', 'type', 'storages', 'volume']
    optional_attrs = [
        'containsSlices',
        'flrClock',
        'internalUse',
        'maxFlrRetentionPeriod',
        'storagePools',
        'virtualProvisioning',
        'dataServicePolicies',
    ]
    check_node(tt, 'FileSystem', required_attrs, optional_attrs)

    list_child = [
        'RwFileSystemHosts',
        'RoFileSystemHosts',
        'FileSystemAutoExtInfo',
        'ProductionFileSystemData',
        'MigrationFileSystemData',
    ]
    child = list_of_various(tt, list_child)

    if len(child) > 0:
        for item in child:
            if (item[0] == 'RwFileSystemHosts' or
                    item[0] == 'RoFileSystemHosts'):
                if 'mover' in item[1].keys():
                    attrs(tt)['mover'] = item[1]['mover']
                if 'moverIdIsVdm' in item[1].keys():
                    attrs(tt)['moverIdIsVdm'] = item[1]['moverIdIsVdm']
            elif item[0] == 'FileSystemAutoExtInfo':
                if 'autoExtEnabled' in item[1].keys():
                    attrs(tt)['autoExtEnabled'] = item[1]['autoExtEnabled']
                if 'autoExtensionMaxSize' in item[1].keys():
                    attrs(tt)['autoExtensionMaxSize'] = (
                        item[1]['autoExtensionMaxSize'])
                if 'highWaterMark' in item[1].keys():
                    attrs(tt)['highWaterMark'] = item[1]['highWaterMark']
            elif item[0] == 'ProductionFileSystemData':
                if 'cwormState' in item[1].keys():
                    attrs(tt)['cwormState'] = item[1]['cwormState']
                if 'replicationRole' in item[1].keys():
                    attrs(tt)['replicationRole'] = item[1]['replicationRole']
            elif item[0] == 'MigrationFileSystemData':
                if 'state' in item[1].keys():
                    attrs(tt)['state'] = item[1]['state']

    return name(tt), attrs(tt)


def parse_rwfilesystemhosts_filesystem(tt):
    check_node(tt, 'RwFileSystemHosts', ['mover'], ['moverIdIsVdm'])

    return name(tt), attrs(tt)


def parse_rofilesystemhosts_filesystem(tt):
    check_node(tt, 'RoFileSystemHosts', ['mover'], ['moverIdIsVdm'])

    return name(tt), attrs(tt)


def parse_rwfilesystemhosts_ckpt(tt):
    check_node(tt, 'rwFileSystemHosts', ['mover'], ['moverIdIsVdm'])

    return name(tt), attrs(tt)


def parse_rofilesystemhosts_ckpt(tt):
    check_node(tt, 'roFileSystemHosts', ['mover'], ['moverIdIsVdm'])

    return name(tt), attrs(tt)


def parse_filesystemautoextinfo(tt):
    required_attrs = []
    optional_attrs = [
        'autoExtEnabled',
        'autoExtensionMaxSize',
        'highWaterMark',
    ]
    check_node(tt, 'FileSystemAutoExtInfo', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_productionfilesystemdata(tt):
    required_attrs = []
    optional_attrs = ['cwormState', 'replicationRole']
    check_node(tt, 'ProductionFileSystemData', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_migrationfilesystemdata(tt):
    check_node(tt, 'MigrationFileSystemData', [], ['state'])

    return name(tt), attrs(tt)


def parse_filesystemcapabilities(tt):
    check_node(tt, 'FileSystemCapabilities', ['fileSystem'], [])

    child = list_of_various(tt, ['StoragePoolBased', 'DiskVolumeBased'])

    if len(child) > 0:
        for item in child:
            if item[0] == 'StoragePoolBased':
                if 'recommendedPool' in item[1].keys():
                    attrs(tt)['recommendedPool'] = item[1]['recommendedPool']
                if 'validPools' in item[1].keys():
                    attrs(tt)['validPools'] = item[1]['validPools']

    return name(tt), attrs(tt)


def parse_storagepoolbased(tt):
    check_node(tt, 'StoragePoolBased', [], ['recommendedPool', 'validPools'])

    return name(tt), attrs(tt)


def parse_diskvolumebased(tt):
    required_attrs = []
    optional_attrs = ['recommendedStorage', 'validStorages']
    check_node(tt, 'DiskVolumeBased', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_filesystemcapacityinfo(tt):
    check_node(tt, 'FileSystemCapacityInfo', ['fileSystem', 'volumeSize'], [])

    child = optional_child(tt, ['ResourceUsage'])

    if child is not None:
        if child[0] == 'ResourceUsage':
            if 'spaceTotal' in child[1].keys():
                attrs(tt)['spaceTotal'] = child[1]['spaceTotal']
            if 'filesUsed' in child[1].keys():
                attrs(tt)['filesUsed'] = child[1]['filesUsed']
            if 'spaceUsed' in child[1].keys():
                attrs(tt)['spaceUsed'] = child[1]['spaceUsed']
            if 'filesTotal' in child[1].keys():
                attrs(tt)['filesTotal'] = child[1]['filesTotal']

    return name(tt), attrs(tt)


def parse_resourceusage(tt):
    required_attrs = ['filesTotal', 'filesUsed', 'spaceTotal', 'spaceUsed']
    check_node(tt, 'ResourceUsage', required_attrs)

    return name(tt), attrs(tt)


def parse_mount(tt):
    required_attrs = ['fileSystem', 'mover', 'path']
    optional_attrs = ['disabled', 'ntCredential', 'moverIdIsVdm']
    check_node(tt, 'Mount', required_attrs, optional_attrs)

    child = list_of_various(tt, ['NfsOptions', 'CifsOptions'])

    if child is not None:
        for item in child:
            if item[0] == 'NfsOptions':
                if 'ro' in item[1].keys():
                    attrs(tt)['ro'] = item[1]['ro']
            if item[0] == 'CifsOptions':
                if 'cifsSyncwrite' in item[1].keys():
                    attrs(tt)['cifsSyncwrite'] = item[1]['cifsSyncwrite']

    return name(tt), attrs(tt)


def parse_nfsoptions(tt):
    required_attrs = []
    optional_attrs = ['ro', 'prefetch', 'uncached', 'virusScan']
    check_node(tt, 'NfsOptions', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_cifsoptions(tt):
    required_attrs = []
    optional_attrs = [
        'cifsSyncwrite',
        'accessPolicy',
        'lockingPolicy',
        'notify',
        'notifyOnAccess',
        'notifyOnWrite',
        'oplock',
        'triggerLevel',
    ]
    check_node(tt, 'CifsOptions', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_cifsshare(tt):
    required_attrs = ['mover', 'name', 'path']
    optional_attrs = ['comment', 'fileSystem', 'maxUsers', 'moverIdIsVdm']
    check_node(tt, 'CifsShare', required_attrs, optional_attrs)

    child = one_child(tt, ['CifsServers'])

    if child is not None:
        attrs(tt)['CifsServers'] = child[1]

    return name(tt), attrs(tt)


def parse_cifsservers(tt):
    check_node(tt, 'CifsServers')

    child = list_of_various(tt, ['li'])

    if len(child) > 0 and child[0] is not None:
        return 'CifsServers', child


def parse_li(tt):
    check_node(tt, 'li', [], [], [], True)

    return ''.join(tt[2])


def parse_cifsserver(tt):
    required_attrs = ['mover', 'name', 'type']
    optional_attrs = ['localUsers', 'interfaces', 'moverIdIsVdm']
    check_node(tt, 'CifsServer', required_attrs, optional_attrs)

    list_child = [
        'Aliases',
        'StandaloneServerData',
        'NT40ServerData',
        'W2KServerData',
    ]
    child = list_of_various(tt, list_child)

    if len(child) > 0:
        for item in child:
            if item[0] == 'Aliases':
                attrs(tt)['aliases'] = item[1]
            elif item[0] == 'W2KServerData':
                if 'domain' in item[1].keys():
                    attrs(tt)['domain'] = item[1]['domain']
                if 'domainJoined' in item[1].keys():
                    attrs(tt)['domainJoined'] = item[1]['domainJoined']
                if 'compName' in item[1].keys():
                    attrs(tt)['compName'] = item[1]['compName']
            elif item[0] == 'NT40ServerData':
                if 'domain' in item[1].keys():
                    attrs(tt)['domain'] = item[1]['domain']

    return name(tt), attrs(tt)


def parse_aliases(tt):
    check_node(tt, 'Aliases')

    child = list_of_various(tt, ['li'])

    if len(child) > 0:
        return 'Aliases', child


def parse_standaloneserverdata(tt):
    check_node(tt, 'StandaloneServerData', ['workgroup'])

    return name(tt), attrs(tt)


def parse_nt40serverdata(tt):
    check_node(tt, 'NT40ServerData', ['domain'])

    return name(tt), attrs(tt)


def parse_w2kserverdata(tt):
    check_node(tt, 'W2KServerData', ['compName', 'domain'], ['domainJoined'])

    return name(tt), attrs(tt)


def parse_volume(tt):
    required_attrs = ['name', 'size', 'type', 'virtualProvisioning', 'volume']
    optional_attrs = ['clientVolumes']
    check_node(tt, 'Volume', required_attrs, optional_attrs)

    list_child = [
        'MetaVolumeData',
        'SliceVolumeData',
        'StripeVolumeData',
        'DiskVolumeData',
        'PoolVolumeData',
        'FreeSpace',
    ]
    child = list_of_various(tt, list_child)

    if len(child) > 0:
        for item in child:
            if item[0] == 'MetaVolumeData':
                if 'memberVolumes' in item[1].keys():
                    attrs(tt)['memberVolumes'] = item[1]['memberVolumes']
                if 'clientFileSystems' in item[1].keys():
                    attrs(tt)['clientFileSystems'] = (
                        item[1]['clientFileSystems'])

    return name(tt), attrs(tt)


def parse_slicevolumedata(tt):
    pass


def parse_stripevolumedata(tt):
    pass


def parse_diskvolumedata(tt):
    pass


def parse_poolvolumedata(tt):
    pass


def parse_freespace(tt):
    pass


def parse_metavolumedata(tt):
    check_node(tt, 'MetaVolumeData', ['memberVolumes'], ['clientFileSystems'])

    return name(tt), attrs(tt)


def parse_storagepool(tt):
    required_attrs = [
        'autoSize',
        'diskType',
        'memberVolumes',
        'movers',
        'name',
        'pool',
        'size',
        'storageSystems',
        'usedSize',
    ]
    optional_attrs = [
        'description',
        'mayContainSlicesDefault',
        'stripeCount',
        'stripeSize',
        'templatePool',
        'virtualProvisioning',
        'dataServicePolicies',
        'isHomogeneous',
    ]
    check_node(tt, 'StoragePool', required_attrs, optional_attrs)

    list_child = ['SystemStoragePoolData', 'UserStoragePoolData']
    child = list_of_various(tt, list_child)

    if len(child) > 0:
        for item in child:
            if item[0] == 'SystemStoragePoolData':
                if 'greedy' in item[1].keys():
                    attrs(tt)['greedy'] = item[1]['greedy']
                if 'isBackendPool' in item[1].keys():
                    attrs(tt)['isBackendPool'] = item[1]['isBackendPool']

    return name(tt), attrs(tt)


def parse_systemstoragepooldata(tt):
    required_attrs = ['potentialAdditionalSize']
    optional_attrs = [
        'greedy',
        'dynamic',
        'isBackendPool',
        'usedSize',
        'size',
    ]
    check_node(tt, 'SystemStoragePoolData', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_userstoragepooldata(tt):
    pass


def parse_fault(tt):
    check_node(tt, 'Fault', ['maxSeverity'])

    child = list_of_various(tt, ['Problem'])

    if len(child) != 0:
        return name(tt), attrs(tt), child
    else:
        return name(tt), attrs(tt)


def parse_packetfault(tt):
    check_node(tt, 'PacketFault', ['maxSeverity'])

    child = list_of_various(tt, ['Problem'])

    if len(child) != 0:
        return name(tt), attrs(tt), child
    else:
        return name(tt), attrs(tt)


def parse_problem(tt):
    required_attrs = ['component', 'messageCode', 'severity']
    optional_attrs = ['facility', 'message']
    check_node(tt, 'Problem', required_attrs, optional_attrs)

    child = list_of_various(tt, ['Description', 'Action', 'Diagnostics'])

    if 0 != len(child):
        for item in child:
            if item is not None:
                if 'Description' in item.keys():
                    attrs(tt)['description'] = item['Description']
                if 'Action' in item.keys():
                    attrs(tt)['action'] = item['Action']
                if 'Diagnostics' in item.keys():
                    attrs(tt)['Diagnostics'] = item['Diagnostics']

    return name(tt), attrs(tt)


def parse_description(tt):
    check_node(tt, 'Description', [], [], [], True)

    if tt[2] is not None:
        return {name(tt): ''.join(tt[2])}


def parse_action(tt):
    pass


def parse_diagnostics(tt):
    check_node(tt, 'Diagnostics', [], [], [], True)

    return {name(tt): ''.join(tt[2])}


def parse_taskresponse(tt):
    check_node(tt, 'TaskResponse', ['taskId'])

    child = one_child(tt, ['Status'])

    if 'maxSeverity' in child[1].keys():
        attrs(tt)['maxSeverity'] = child[1]['maxSeverity']

    if len(child) == 2:
        return name(tt), attrs(tt)
    else:
        return name(tt), attrs(tt), child[2]


def parse_status(tt):
    check_node(tt, 'Status', ['maxSeverity'])

    child = list_of_various(tt, ['Problem'])

    if child:
        return name(tt), attrs(tt), child
    else:
        return name(tt), attrs(tt)


def parse_checkpoint(tt):
    required_attrs = ['checkpoint', 'name', 'state', 'time']
    optional_attrs = [
        'baseline',
        'checkpointOf',
        'fileSystemSize',
        'writeable',
    ]
    check_node(tt, 'Checkpoint', required_attrs, optional_attrs)

    child = list_of_various(tt, ['rwFileSystemHosts', 'roFileSystemHosts'])

    for item in child:
        if item[0] == 'rwFileSystemHosts' or item[0] == 'roFileSystemHosts':
            if 'mover' in item[1].keys():
                attrs(tt)['mover'] = item[1]['mover']
            if 'moverIdIsVdm' in item[1].keys():
                attrs(tt)['moverIdIsVdm'] = item[1]['moverIdIsVdm']

            if item[0] == 'roFileSystemHosts':
                attrs(tt)['readOnly'] = True
            else:
                attrs(tt)['readOnly'] = False

    return name(tt), attrs(tt)


def parse_nfsexport(tt):
    required_attrs = ['mover', 'path']
    optional_attrs = ['anonUser', 'fileSystem', 'readOnly']
    check_node(tt, 'NfsExport', required_attrs, optional_attrs)

    list_child = ['AccessHosts', 'RwHosts', 'RoHosts', 'RootHosts']
    child = list_of_various(tt, list_child)

    for item in child:
        if 'AccessHosts' in item.keys():
            attrs(tt)['AccessHosts'] = item['AccessHosts']

        if 'RwHosts' in item.keys():
            attrs(tt)['RwHosts'] = item['RwHosts']

        if 'RoHosts' in item.keys():
            attrs(tt)['RoHosts'] = item['RoHosts']

        if 'RootHosts' in item.keys():
            attrs(tt)['RootHosts'] = item['RootHosts']

    return name(tt), attrs(tt)


def parse_accesshosts(tt):
    check_node(tt, 'AccessHosts')

    access_hosts = []

    child = list_of_various(tt, ['li'])

    for item in child:
        if item != '':
            access_hosts.append(item)

    return {'AccessHosts': access_hosts}


def parse_rwhosts(tt):
    check_node(tt, 'RwHosts')

    rw_hosts = []

    child = list_of_various(tt, ['li'])

    for item in child:
        if item != '':
            rw_hosts.append(item)

    return {'RwHosts': rw_hosts}


def parse_rohosts(tt):
    check_node(tt, 'RoHosts')

    ro_hosts = []

    child = list_of_various(tt, ['li'])

    for item in child:
        if item != '':
            ro_hosts.append(item)

    return {'RoHosts': ro_hosts}


def parse_roothosts(tt):
    check_node(tt, 'RootHosts')

    root_hosts = []

    child = list_of_various(tt, ['li'])

    for item in child:
        if item != '':
            root_hosts.append(item)

    return {'RootHosts': root_hosts}


def parse_mover(tt):
    required_attrs = ['host', 'mover', 'name']
    optional_attrs = [
        'failoverPolicy',
        'i18NMode',
        'ntpServers',
        'role',
        'standbyFors',
        'standbys',
        'targetState',
    ]
    check_node(tt, 'Mover', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_moverstatus(tt):
    required_attrs = ['csTime', 'mover', 'uptime']
    optional_attrs = ['clock', 'timezone', 'version']
    check_node(tt, 'MoverStatus', required_attrs, optional_attrs)

    child = one_child(tt, ['Status'])

    if len(child) >= 2:
        attrs(tt)['Status'] = child[1]['maxSeverity']

    if len(child) >= 3:
        attrs(tt)['Problem'] = child[2]

    return name(tt), attrs(tt)


def parse_moverdnsdomain(tt):
    required_attrs = ['mover', 'name', 'servers']
    optional_attrs = ['protocol']
    check_node(tt, 'MoverDnsDomain', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_moverinterface(tt):
    required_attrs = ['device', 'ipAddress', 'macAddr', 'mover', 'name']
    optional_attrs = [
        'broadcastAddr',
        'ipVersion',
        'mtu',
        'netMask',
        'up',
        'vlanid',
    ]
    check_node(tt, 'MoverInterface', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_moverroute(tt):
    required_attrs = ['mover']
    optional_attrs = [
        'destination',
        'interface',
        'ipVersion',
        'netMask',
        'gateway',
    ]
    check_node(tt, 'MoverRoute', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_logicalnetworkdevice(tt):
    required_attrs = ['mover', 'name', 'speed', 'type']
    optional_attrs = ['interfaces']
    check_node(tt, 'LogicalNetworkDevice', required_attrs, optional_attrs)

    return name(tt), attrs(tt)


def parse_moverdeduplicationsettings(tt):
    required_attrs = ['mover']
    optional_attrs = [
        'accessTime',
        'modificationTime',
        'maximumSize',
        'minimumSize',
        'caseSensitive',
        'duplicateDetectionMethod',
        'minimumScanInterval',
        'fileExtensionExcludeList',
        'savVolHighWatermark',
        'backupDataHighWatermark',
        'CPULowWatermark',
        'CPUHighWatermark',
        'cifsCompressionEnabled',
    ]
    check_node(tt,
               'MoverDeduplicationSettings',
               required_attrs,
               optional_attrs)

    return name(tt), attrs(tt)


def parse_vdm(tt):
    required_attrs = ['name', 'state', 'vdm']
    optional_attrs = ['mover', 'rootFileSystem']
    check_node(tt, 'Vdm', required_attrs, optional_attrs)

    child = list_of_various(tt, ['Status', 'Interfaces'])

    if len(child) > 0:
        for item in child:
            if 'Interfaces' == item[0]:
                attrs(tt)['Interfaces'] = item[1]

    return name(tt), attrs(tt)


def parse_interfaces(tt):
    check_node(tt, 'Interfaces')

    interfaces = []

    child = list_of_various(tt, ['li'])

    for item in child:
        if item != '':
            interfaces.append(item)

    if interfaces:
        return 'Interfaces', interfaces


def one_child(tt, acceptable):
    """Parse children of a node with exactly one child node.

    PCData is ignored.
    """
    k = kids(tt)

    if len(k) != 1:
        message = (_('Expected just one %(item)s, got %(more)s.')
                   % {'item': acceptable,
                      'more': " ".join([t[0] for t in k])})
        LOG.warn(message)

    child = k[0]

    if name(child) not in acceptable:
        message = (_('Expected one of %(item)s, got %(child)s '
                     'under %(parent)s.')
                   % {'item': acceptable,
                      'child': name(child),
                      'parent': name(tt)})

    return parse_any(child)


def parse_any(tt):
    """Parse any fragment of XML."""

    node_name = name(tt).replace('.', '_')

    # Special handle for file system and checkpoint
    if node_name == 'RwFileSystemHosts' or node_name == 'RoFileSystemHosts':
        node_name += '_filesystem'
    elif node_name == 'rwFileSystemHosts' or node_name == 'roFileSystemHosts':
        node_name += '_ckpt'

    fn_name = 'parse_' + node_name.lower()
    fn = globals().get(fn_name)
    if fn is None:
        message = _('No parser for node type %s.') % name(tt)
        LOG.warn(message)
    else:
        return fn(tt)


def check_node(tt, nodename, required_attrs=None, optional_attrs=None,
               allowed_children=None, allow_pcdata=False):
    """Check static local constraints on a single node.

    The node must have the given name.  The required attrs must be
    present, and the optional attrs may be.

    If allowed_children is not None, the node may have children of the
    given types.  It can be [] for nodes that may not have any
    children.  If it's None, it is assumed the children are validated
    in some other way.

    If allow_pcdata is true, then non-whitespace text children are allowed.
    (Whitespace text nodes are always allowed.)
    """
    if not optional_attrs:
        optional_attrs = []

    if not required_attrs:
        required_attrs = []

    if name(tt) != nodename:
        message = (_('Expected node type %(expected)s, not %(actual)s.')
                   % {'expected': nodename, 'actual': name(tt)})
        LOG.warn(message)

    # Check we have all the required attributes, and no unexpected ones
    tt_attrs = {}
    if attrs(tt) is not None:
        tt_attrs = attrs(tt).copy()

    for attr in required_attrs:
        if attr not in tt_attrs:
            message = (_('Expected %(attr)s attribute on %(node)s node,'
                         ' but only have %(attrs)s.')
                       % {'attr': attr,
                          'node': name(tt),
                          'attrs': attrs(tt).keys()})
            LOG.warn(message)
        else:
            del tt_attrs[attr]

    for attr in optional_attrs:
        if attr in tt_attrs:
            del tt_attrs[attr]

    if len(tt_attrs.keys()) > 0:
        message = _('Invalid extra attributes %s.') % tt_attrs.keys()
        LOG.warn(message)

    if allowed_children is not None:
        for c in kids(tt):
            if name(c) not in allowed_children:
                message = (_('Unexpected node %(node)s under %(parent)s;'
                             ' wanted %(expected)s.')
                           % {'node': name(c),
                              'parent': name(tt),
                              'expected': allowed_children})
                LOG.warn(message)

    if not allow_pcdata:
        for c in tt[2]:
            if isinstance(c, types.StringTypes):
                if c.lstrip(' \t\n') != '':
                    message = (_('Unexpected non-blank pcdata node %(node)s'
                                 ' under %(parent)s.')
                               % {'node': repr(c),
                                  'parent': name(tt)})
                    LOG.warn(message)


def optional_child(tt, allowed):
    """Parse zero or one of a list of elements from the child nodes."""

    k = kids(tt)

    if len(k) > 1:
        message = (_('Expected either zero or one of %(node)s '
                     'under %(parent)s.') % {'node': allowed,
                                             'parent': tt})
        LOG.warn(message)
    elif len(k) == 1:
        return one_child(tt, allowed)
    else:
        return None


def list_of_various(tt, acceptable):
    """Parse zero or more of a list of elements from the child nodes.

    Each element of the list can be any type from the list of the acceptable
    nodes.
    """

    r = []

    for child in kids(tt):
        if name(child) not in acceptable:
            message = (_('Expected one of %(expected)s under'
                         ' %(parent)s, got %(actual)s.')
                       % {'expected': acceptable,
                          'parent': name(tt),
                          'actual': repr(name(child))})
            LOG.warn(message)
        result = parse_any(child)
        if result is not None:
            r.append(result)

    return r


def dom_to_tupletree(node):
    """Convert a DOM object to a pyRXP-style tuple tree.

    Each element is a 4-tuple of (NAME, ATTRS, CONTENTS, None).

    Very nice for processing complex nested trees.
    """

    if node.nodeType == node.DOCUMENT_NODE:
        # boring; pop down one level
        return dom_to_tupletree(node.firstChild)
    assert node.nodeType == node.ELEMENT_NODE

    node_name = node.nodeName
    attributes = {}
    contents = []

    for child in node.childNodes:
        if child.nodeType == child.ELEMENT_NODE:
            contents.append(dom_to_tupletree(child))
        elif child.nodeType == child.TEXT_NODE:
            msg = "text node %s is not a string" % repr(child)
            assert isinstance(child.nodeValue, types.StringTypes), msg
            contents.append(child.nodeValue)
        else:
            raise RuntimeError("can't handle %s" % child)

    for i in range(node.attributes.length):
        attr_node = node.attributes.item(i)
        attributes[attr_node.nodeName] = attr_node.nodeValue

    return node_name, attributes, contents, None


def xml_to_tupletree(xml_string):
    """Parse XML straight into tupletree."""
    dom_xml = xml.dom.minidom.parseString(xml_string)
    return dom_to_tupletree(dom_xml)
