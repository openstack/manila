# Copyright (c) 2015 Clinton Knight  All rights reserved.
# Copyright (c) 2015 Tom Barron  All rights reserved.
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

import copy

from manila.common import constants
import manila.tests.share.drivers.netapp.fakes as na_fakes


BACKEND_NAME = 'fake_backend_name'
DRIVER_NAME = 'fake_driver_name'
APP_VERSION = 'fake_app_vsersion'
HOST_NAME = 'fake_host'
POOL_NAME = 'fake_pool'
VSERVER1 = 'fake_vserver_1'
VSERVER2 = 'fake_vserver_2'
LICENSES = ('base', 'cifs', 'fcp', 'flexclone', 'iscsi', 'nfs', 'snapmirror',
            'snaprestore', 'snapvault')
VOLUME_NAME_TEMPLATE = 'share_%(share_id)s'
VSERVER_NAME_TEMPLATE = 'os_%s'
AGGREGATE_NAME_SEARCH_PATTERN = '(.*)'
SHARE_NAME = 'share_7cf7c200_d3af_4e05_b87e_9167c95dfcad'
FLEXVOL_NAME = 'fake_volume'
JUNCTION_PATH = '/%s' % FLEXVOL_NAME
EXPORT_LOCATION = '%s:%s' % (HOST_NAME, JUNCTION_PATH)
SNAPSHOT_NAME = 'fake_snapshot'
SNAPSHOT_ACCESS_TIME = '1466455782'
CONSISTENCY_GROUP_NAME = 'fake_consistency_group'
SHARE_SIZE = 10
TENANT_ID = '24cb2448-13d8-4f41-afd9-eff5c4fd2a57'
SHARE_ID = '7cf7c200-d3af-4e05-b87e-9167c95dfcad'
SHARE_ID2 = 'b51c5a31-aa5b-4254-9ee8-7d39fa4c8c38'
SHARE_ID3 = '1379991d-037b-4897-bf3a-81b4aac72eff'
SHARE_ID4 = '1cb41aad-fd9b-4964-8059-646f69de925e'
PARENT_SHARE_ID = '585c3935-2aa9-437c-8bad-5abae1076555'
SNAPSHOT_ID = 'de4c9050-e2f9-4ce1-ade4-5ed0c9f26451'
CONSISTENCY_GROUP_ID = '65bfa2c9-dc6c-4513-951a-b8d15b453ad8'
CONSISTENCY_GROUP_ID2 = '35f5c1ea-45fb-40c4-98ae-2a2a17554159'
CG_SNAPSHOT_ID = '6ddd8a6b-5df7-417b-a2ae-3f6e449f4eea'
CG_SNAPSHOT_MEMBER_ID1 = '629f79ef-b27e-4596-9737-30f084e5ba29'
CG_SNAPSHOT_MEMBER_ID2 = 'e876aa9c-a322-4391-bd88-9266178262be'
FREE_CAPACITY = 10000000000
TOTAL_CAPACITY = 20000000000
AGGREGATE = 'manila_aggr_1'
AGGREGATES = ('manila_aggr_1', 'manila_aggr_2')
ROOT_AGGREGATES = ('root_aggr_1', 'root_aggr_2')
ROOT_VOLUME_AGGREGATE = 'manila1'
ROOT_VOLUME = 'root'
CLUSTER_NODE = 'cluster1_01'
CLUSTER_NODES = ('cluster1_01', 'cluster1_02')
NODE_DATA_PORT = 'e0c'
NODE_DATA_PORTS = ('e0c', 'e0d')
LIF_NAME_TEMPLATE = 'os_%(net_allocation_id)s'
SHARE_TYPE_ID = '26e89a5b-960b-46bb-a8cf-0778e653098f'
SHARE_TYPE_NAME = 'fake_share_type'
IPSPACE = 'fake_ipspace'
IPSPACE_ID = '27d38c27-3e8b-4d7d-9d91-fcf295e3ac8f'
MTU = 1234
DEFAULT_MTU = 1500
MANILA_HOST_NAME = '%(host)s@%(backend)s#%(pool)s' % {
    'host': HOST_NAME, 'backend': BACKEND_NAME, 'pool': POOL_NAME}
QOS_EXTRA_SPEC = 'netapp:maxiops'
QOS_SIZE_DEPENDENT_EXTRA_SPEC = 'netapp:maxbpspergib'
QOS_NORMALIZED_SPEC = 'maxiops'
QOS_POLICY_GROUP_NAME = 'fake_qos_policy_group_name'

CLIENT_KWARGS = {
    'username': 'admin',
    'trace': False,
    'hostname': '127.0.0.1',
    'vserver': None,
    'transport_type': 'https',
    'password': 'pass',
    'port': '443',
    'api_trace_pattern': '(.*)',
}

SHARE = {
    'id': SHARE_ID,
    'host': MANILA_HOST_NAME,
    'project_id': TENANT_ID,
    'name': SHARE_NAME,
    'size': SHARE_SIZE,
    'share_proto': 'fake',
    'share_type_id': 'fake_share_type_id',
    'share_network_id': '5dfe0898-e2a1-4740-9177-81c7d26713b0',
    'share_server_id': '7e6a2cc8-871f-4b1d-8364-5aad0f98da86',
    'network_info': {
        'network_allocations': [{'ip_address': 'ip'}]
    },
    'replica_state': constants.REPLICA_STATE_ACTIVE,
    'status': constants.STATUS_AVAILABLE,
    'share_server': None,
    'encrypt': False,
}

FLEXVOL_TO_MANAGE = {
    'aggregate': POOL_NAME,
    'junction-path': '/%s' % FLEXVOL_NAME,
    'name': FLEXVOL_NAME,
    'type': 'rw',
    'style': 'flex',
    'size': '1610612736',  # rounds up to 2 GB
}

FLEXVOL_WITHOUT_QOS = copy.deepcopy(FLEXVOL_TO_MANAGE)
FLEXVOL_WITHOUT_QOS.update({'qos-policy-group-name': None})
FLEXVOL_WITH_QOS = copy.deepcopy(FLEXVOL_TO_MANAGE)
FLEXVOL_WITH_QOS.update({'qos-policy-group-name': QOS_POLICY_GROUP_NAME})

QOS_POLICY_GROUP = {
    'policy-group': QOS_POLICY_GROUP_NAME,
    'vserver': VSERVER1,
    'max-throughput': '3000iops',
    'num-workloads': 1,
}

FLEXVOL = {
    'aggregate': POOL_NAME,
    'junction-path': '/%s' % FLEXVOL_NAME,
    'name': FLEXVOL_NAME,
    'type': 'rw',
    'style': 'flex',
    'size': '1610612736',  # rounds down to 1 GB,
    'owning-vserver-name': VSERVER1,
}

EXTRA_SPEC = {
    'netapp:thin_provisioned': 'true',
    'netapp:snapshot_policy': 'default',
    'netapp:language': 'en-US',
    'netapp:dedup': 'True',
    'netapp:compression': 'false',
    'netapp:max_files': 5000,
    'netapp:split_clone_on_create': 'true',
    'netapp_disk_type': 'FCAL',
    'netapp_raid_type': 'raid4',
    'netapp_flexvol_encryption': 'true',
}

EXTRA_SPEC_WITH_QOS = copy.deepcopy(EXTRA_SPEC)
EXTRA_SPEC_WITH_QOS.update({
    'qos': True,
    QOS_EXTRA_SPEC: '3000',
})

EXTRA_SPEC_WITH_SIZE_DEPENDENT_QOS = copy.deepcopy(EXTRA_SPEC)
EXTRA_SPEC_WITH_SIZE_DEPENDENT_QOS.update({
    'qos': True,
    QOS_SIZE_DEPENDENT_EXTRA_SPEC: '1000',
})

PROVISIONING_OPTIONS = {
    'thin_provisioned': True,
    'snapshot_policy': 'default',
    'language': 'en-US',
    'dedup_enabled': True,
    'compression_enabled': False,
    'max_files': 5000,
    'split': True,
    'encrypt': False,
}

PROVISIONING_OPTIONS_WITH_QOS = copy.deepcopy(PROVISIONING_OPTIONS)
PROVISIONING_OPTIONS_WITH_QOS.update(
    {'qos_policy_group': QOS_POLICY_GROUP_NAME})

PROVISIONING_OPTIONS_BOOLEAN = {
    'thin_provisioned': True,
    'dedup_enabled': False,
    'compression_enabled': False,
    'split': False,
}

PROVISIONING_OPTIONS_BOOLEAN_THIN_PROVISIONED_TRUE = {
    'thin_provisioned': True,
    'snapshot_policy': None,
    'language': None,
    'dedup_enabled': False,
    'compression_enabled': False,
    'max_files': None,
    'split': False,
    'encrypt': False,
}

PROVISIONING_OPTIONS_STRING = {
    'snapshot_policy': 'default',
    'language': 'en-US',
    'max_files': 5000,
}

PROVISIONING_OPTIONS_STRING_MISSING_SPECS = {
    'snapshot_policy': 'default',
    'language': 'en-US',
    'max_files': None,
}

PROVISIONING_OPTIONS_STRING_DEFAULT = {
    'snapshot_policy': None,
    'language': None,
    'max_files': None,
}

SHORT_BOOLEAN_EXTRA_SPEC = {
    'netapp:thin_provisioned': 'true',
}

STRING_EXTRA_SPEC = {
    'netapp:snapshot_policy': 'default',
    'netapp:language': 'en-US',
    'netapp:max_files': 5000,
}

SHORT_STRING_EXTRA_SPEC = {
    'netapp:snapshot_policy': 'default',
    'netapp:language': 'en-US',
}

INVALID_EXTRA_SPEC = {
    'netapp:thin_provisioned': 'ture',
    'netapp:snapshot_policy': 'wrong_default',
    'netapp:language': 'abc',
}

INVALID_EXTRA_SPEC_COMBO = {
    'netapp:dedup': 'false',
    'netapp:compression': 'true'
}

INVALID_MAX_FILE_EXTRA_SPEC = {
    'netapp:max_files': -1,
}

EMPTY_EXTRA_SPEC = {}

SHARE_TYPE = {
    'id': SHARE_TYPE_ID,
    'name': SHARE_TYPE_NAME,
    'extra_specs': EXTRA_SPEC
}

OVERLAPPING_EXTRA_SPEC = {
    'compression': '<is> True',
    'netapp:compression': 'true',
    'dedupe': '<is> True',
    'netapp:dedup': 'false',
    'thin_provisioning': '<is> False',
    'netapp:thin_provisioned': 'true',
}

REMAPPED_OVERLAPPING_EXTRA_SPEC = {
    'netapp:compression': 'true',
    'netapp:dedup': 'true',
    'netapp:thin_provisioned': 'false',
}

EXTRA_SPEC_SHARE = copy.deepcopy(SHARE)
EXTRA_SPEC_SHARE['share_type_id'] = SHARE_TYPE_ID

USER_NETWORK_ALLOCATIONS = [
    {
        'id': '132dbb10-9a36-46f2-8d89-3d909830c356',
        'ip_address': '10.10.10.10',
        'cidr': '10.10.10.0/24',
        'segmentation_id': '1000',
        'network_type': 'vlan',
        'label': 'user',
        'mtu': MTU,
        'gateway': '10.10.10.1',
    },
    {
        'id': '7eabdeed-bad2-46ea-bd0f-a33884c869e0',
        'ip_address': '10.10.10.20',
        'cidr': '10.10.10.0/24',
        'segmentation_id': '1000',
        'network_type': 'vlan',
        'label': 'user',
        'mtu': MTU,
        'gateway': '10.10.10.1',
    }
]

USER_NETWORK_ALLOCATIONS_IPV6 = [
    {
        'id': '234dbb10-9a36-46f2-8d89-3d909830c356',
        'ip_address': 'fd68:1a09:66ab:8d51:0:10:0:1',
        'cidr': 'fd68:1a09:66ab:8d51::/64',
        'segmentation_id': '2000',
        'network_type': 'vlan',
        'label': 'user',
        'mtu': MTU,
        'gateway': 'fd68:1a09:66ab:8d51:0:0:0:1',
    },
    {
        'id': '6677deed-bad2-46ea-bd0f-a33884c869e0',
        'ip_address': 'fd68:1a09:66ab:8d51:0:10:0:2',
        'cidr': 'fd68:1a09:66ab:8d51::/64',
        'segmentation_id': '2000',
        'network_type': 'vlan',
        'label': 'user',
        'mtu': MTU,
        'gateway': 'fd68:1a09:66ab:8d51:0:0:0:1',
    }
]

ADMIN_NETWORK_ALLOCATIONS = [
    {
        'id': '132dbb10-9a36-46f2-8d89-3d909830c356',
        'ip_address': '10.10.20.10',
        'cidr': '10.10.20.0/24',
        'segmentation_id': None,
        'network_type': 'flat',
        'label': 'admin',
        'mtu': MTU,
        'gateway': '10.10.20.1'
    },
]

NETWORK_INFO = {
    'server_id': '56aafd02-4d44-43d7-b784-57fc88167224',
    'security_services': ['fake_ldap', 'fake_kerberos', 'fake_ad', ],
    'network_allocations': USER_NETWORK_ALLOCATIONS,
    'admin_network_allocations': ADMIN_NETWORK_ALLOCATIONS,
    'neutron_subnet_id': '62bf1c2c-18eb-421b-8983-48a6d39aafe0',
    'segmentation_id': '1000',
}
NETWORK_INFO_NETMASK = '255.255.255.0'

SHARE_SERVER = {
    'share_network_id': 'c5b3a865-56d0-4d88-abe5-879965e099c9',
    'backend_details': {
        'vserver_name': VSERVER1
    },
    'network_allocations': (USER_NETWORK_ALLOCATIONS +
                            ADMIN_NETWORK_ALLOCATIONS),
}

SNAPSHOT = {
    'id': SNAPSHOT_ID,
    'project_id': TENANT_ID,
    'share_id': PARENT_SHARE_ID,
    'status': constants.STATUS_CREATING,
    'provider_location': None,
}

SNAPSHOT_TO_MANAGE = {
    'id': SNAPSHOT_ID,
    'project_id': TENANT_ID,
    'share_id': PARENT_SHARE_ID,
    'status': constants.STATUS_CREATING,
    'provider_location': SNAPSHOT_NAME,
}

CDOT_SNAPSHOT = {
    'name': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'busy': False,
    'owners': set(),
    'access-time': SNAPSHOT_ACCESS_TIME,
}

CDOT_SNAPSHOT_BUSY_VOLUME_CLONE = {
    'name': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'busy': True,
    'owners': {'volume clone'},
    'access-time': SNAPSHOT_ACCESS_TIME,
}

CDOT_SNAPSHOT_BUSY_SNAPMIRROR = {
    'name': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'busy': True,
    'owners': {'snapmirror'},
    'access-time': SNAPSHOT_ACCESS_TIME,
}

CDOT_CLONE_CHILD_1 = 'fake_child_1'
CDOT_CLONE_CHILD_2 = 'fake_child_2'
CDOT_CLONE_CHILDREN = [
    {'name': CDOT_CLONE_CHILD_1},
    {'name': CDOT_CLONE_CHILD_2},
]

SHARE_FOR_CG1 = {
    'id': SHARE_ID,
    'host': '%(host)s@%(backend)s#%(pool)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME, 'pool': POOL_NAME},
    'name': 'share_1',
    'share_proto': 'NFS',
    'source_share_group_snapshot_member_id': None,
}

SHARE_FOR_CG2 = {
    'id': SHARE_ID2,
    'host': '%(host)s@%(backend)s#%(pool)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME, 'pool': POOL_NAME},
    'name': 'share_2',
    'share_proto': 'NFS',
    'source_share_group_snapshot_member_id': None,
}

# Clone dest of SHARE_FOR_CG1
SHARE_FOR_CG3 = {
    'id': SHARE_ID3,
    'host': '%(host)s@%(backend)s#%(pool)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME, 'pool': POOL_NAME},
    'name': 'share3',
    'share_proto': 'NFS',
    'source_share_group_snapshot_member_id': CG_SNAPSHOT_MEMBER_ID1,
}

# Clone dest of SHARE_FOR_CG2
SHARE_FOR_CG4 = {
    'id': SHARE_ID4,
    'host': '%(host)s@%(backend)s#%(pool)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME, 'pool': POOL_NAME},
    'name': 'share4',
    'share_proto': 'NFS',
    'source_share_group_snapshot_member_id': CG_SNAPSHOT_MEMBER_ID2,
}

EMPTY_CONSISTENCY_GROUP = {
    'cgsnapshots': [],
    'description': 'fake description',
    'host': '%(host)s@%(backend)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME},
    'id': CONSISTENCY_GROUP_ID,
    'name': CONSISTENCY_GROUP_NAME,
    'shares': [],
}

CONSISTENCY_GROUP = {
    'cgsnapshots': [],
    'description': 'fake description',
    'host': '%(host)s@%(backend)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME},
    'id': CONSISTENCY_GROUP_ID,
    'name': CONSISTENCY_GROUP_NAME,
    'shares': [SHARE_FOR_CG1, SHARE_FOR_CG2],
}

CONSISTENCY_GROUP_DEST = {
    'cgsnapshots': [],
    'description': 'fake description',
    'host': '%(host)s@%(backend)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME},
    'id': CONSISTENCY_GROUP_ID,
    'name': CONSISTENCY_GROUP_NAME,
    'shares': [SHARE_FOR_CG3, SHARE_FOR_CG4],
}

CG_SNAPSHOT_MEMBER_1 = {
    'cgsnapshot_id': CG_SNAPSHOT_ID,
    'id': CG_SNAPSHOT_MEMBER_ID1,
    'share_id': SHARE_ID,
    'share_proto': 'NFS',
    'size': SHARE_SIZE,
}

CG_SNAPSHOT_MEMBER_2 = {
    'cgsnapshot_id': CG_SNAPSHOT_ID,
    'id': CG_SNAPSHOT_MEMBER_ID2,
    'share_id': SHARE_ID2,
    'share_proto': 'NFS',
    'size': SHARE_SIZE,
}

CG_SNAPSHOT = {
    'share_group_snapshot_members': [CG_SNAPSHOT_MEMBER_1,
                                     CG_SNAPSHOT_MEMBER_2],
    'share_group': CONSISTENCY_GROUP,
    'share_group_id': CONSISTENCY_GROUP_ID,
    'id': CG_SNAPSHOT_ID,
    'project_id': TENANT_ID,
}

COLLATED_CGSNAPSHOT_INFO = [
    {
        'share': SHARE_FOR_CG3,
        'snapshot': {
            'share_id': SHARE_ID,
            'id': CG_SNAPSHOT_ID,
            'size': SHARE_SIZE,
        }
    },
    {
        'share': SHARE_FOR_CG4,
        'snapshot': {
            'share_id': SHARE_ID2,
            'id': CG_SNAPSHOT_ID,
            'size': SHARE_SIZE,
        }
    },
]

LIF_NAMES = []
LIF_ADDRESSES = ['10.10.10.10', '10.10.10.20']
LIFS = (
    {'address': LIF_ADDRESSES[0],
     'home-node': CLUSTER_NODES[0],
     'home-port': 'e0c',
     'interface-name': 'os_132dbb10-9a36-46f2-8d89-3d909830c356',
     'netmask': NETWORK_INFO_NETMASK,
     'role': 'data',
     'vserver': VSERVER1
     },
    {'address': LIF_ADDRESSES[1],
     'home-node': CLUSTER_NODES[1],
     'home-port': 'e0c',
     'interface-name': 'os_7eabdeed-bad2-46ea-bd0f-a33884c869e0',
     'netmask': NETWORK_INFO_NETMASK,
     'role': 'data',
     'vserver': VSERVER1
     },
)

INTERFACE_ADDRESSES_WITH_METADATA = {
    LIF_ADDRESSES[0]: {
        'is_admin_only': False,
        'preferred': True,
    },
    LIF_ADDRESSES[1]: {
        'is_admin_only': True,
        'preferred': False,
    },
}

NFS_EXPORTS = [
    {
        'path': ':'.join([LIF_ADDRESSES[0], 'fake_export_path']),
        'is_admin_only': False,
        'metadata': {
            'preferred': True,
        },
    },
    {
        'path': ':'.join([LIF_ADDRESSES[1], 'fake_export_path']),
        'is_admin_only': True,
        'metadata': {
            'preferred': False,
        },
    },
]

SHARE_ACCESS = {
    'access_type': 'user',
    'access_to': [LIF_ADDRESSES[0]]
}

EMS_MESSAGE_0 = {
    'computer-name': HOST_NAME,
    'event-id': '0',
    'event-source': 'Manila driver %s' % DRIVER_NAME,
    'app-version': APP_VERSION,
    'category': 'provisioning',
    'event-description': 'OpenStack Manila connected to cluster node',
    'log-level': '5',
    'auto-support': 'false'
}

EMS_MESSAGE_1 = {
    'computer-name': HOST_NAME,
    'event-id': '1',
    'event-source': 'Manila driver %s' % DRIVER_NAME,
    'app-version': APP_VERSION,
    'category': 'provisioning',
    'event-description': '',
    'log-level': '5',
    'auto-support': 'false'
}

AGGREGATE_CAPACITIES = {
    AGGREGATES[0]: {
        'available': 1181116007,  # 1.1 GB
        'total': 3543348020,      # 3.3 GB
        'used': 2362232013,       # 2.2 GB
    },
    AGGREGATES[1]: {
        'available': 2147483648,  # 2.0 GB
        'total': 6442450944,      # 6.0 GB
        'used': 4294967296,       # 4.0 GB
    }
}

AGGREGATE_CAPACITIES_VSERVER_CREDS = {
    AGGREGATES[0]: {
        'available': 1181116007,  # 1.1 GB
    },
    AGGREGATES[1]: {
        'available': 2147483648,  # 2.0 GB
    }
}

SSC_INFO = {
    AGGREGATES[0]: {
        'netapp_raid_type': 'raid4',
        'netapp_disk_type': 'FCAL',
        'netapp_hybrid_aggregate': 'false',
        'netapp_aggregate': AGGREGATES[0],
    },
    AGGREGATES[1]: {
        'netapp_raid_type': 'raid_dp',
        'netapp_disk_type': ['SATA', 'SSD'],
        'netapp_hybrid_aggregate': 'true',
        'netapp_aggregate': AGGREGATES[1],
    }
}

SSC_INFO_VSERVER_CREDS = {
    AGGREGATES[0]: {
        'netapp_aggregate': AGGREGATES[0],
    },
    AGGREGATES[1]: {
        'netapp_aggregate': AGGREGATES[1],
    }
}

POOLS = [
    {
        'pool_name': AGGREGATES[0],
        'netapp_aggregate': AGGREGATES[0],
        'total_capacity_gb': 3.3,
        'free_capacity_gb': 1.1,
        'allocated_capacity_gb': 2.2,
        'qos': 'False',
        'reserved_percentage': 5,
        'dedupe': [True, False],
        'compression': [True, False],
        'thin_provisioning': [True, False],
        'netapp_flexvol_encryption': True,
        'netapp_raid_type': 'raid4',
        'netapp_disk_type': 'FCAL',
        'netapp_hybrid_aggregate': 'false',
        'utilization': 30.0,
        'filter_function': 'filter',
        'goodness_function': 'goodness',
        'snapshot_support': True,
        'create_share_from_snapshot_support': True,
        'revert_to_snapshot_support': True,
        'qos': True,
    },
    {
        'pool_name': AGGREGATES[1],
        'netapp_aggregate': AGGREGATES[1],
        'total_capacity_gb': 6.0,
        'free_capacity_gb': 2.0,
        'allocated_capacity_gb': 4.0,
        'qos': 'False',
        'reserved_percentage': 5,
        'dedupe': [True, False],
        'compression': [True, False],
        'thin_provisioning': [True, False],
        'netapp_flexvol_encryption': True,
        'netapp_raid_type': 'raid_dp',
        'netapp_disk_type': ['SATA', 'SSD'],
        'netapp_hybrid_aggregate': 'true',
        'utilization': 42.0,
        'filter_function': 'filter',
        'goodness_function': 'goodness',
        'snapshot_support': True,
        'create_share_from_snapshot_support': True,
        'revert_to_snapshot_support': True,
        'qos': True,
    },
]

POOLS_VSERVER_CREDS = [
    {
        'pool_name': AGGREGATES[0],
        'netapp_aggregate': AGGREGATES[0],
        'total_capacity_gb': 'unknown',
        'free_capacity_gb': 1.1,
        'allocated_capacity_gb': 0.0,
        'qos': 'False',
        'reserved_percentage': 5,
        'dedupe': [True, False],
        'compression': [True, False],
        'thin_provisioning': [True, False],
        'netapp_flexvol_encryption': True,
        'utilization': 50.0,
        'filter_function': None,
        'goodness_function': None,
        'snapshot_support': True,
        'create_share_from_snapshot_support': True,
        'revert_to_snapshot_support': True,
        'qos': False,
    },
    {
        'pool_name': AGGREGATES[1],
        'netapp_aggregate': AGGREGATES[1],
        'total_capacity_gb': 'unknown',
        'free_capacity_gb': 2.0,
        'allocated_capacity_gb': 0.0,
        'qos': 'False',
        'reserved_percentage': 5,
        'dedupe': [True, False],
        'compression': [True, False],
        'thin_provisioning': [True, False],
        'netapp_flexvol_encryption': True,
        'utilization': 50.0,
        'filter_function': None,
        'goodness_function': None,
        'snapshot_support': True,
        'create_share_from_snapshot_support': True,
        'revert_to_snapshot_support': True,
        'qos': False,
    },
]

SSC_AGGREGATES = [
    {
        'name': AGGREGATES[0],
        'raid-type': 'raid4',
        'is-hybrid': False,
    },
    {
        'name': AGGREGATES[1],
        'raid-type': 'raid_dp',
        'is-hybrid': True,
    },
]

CLUSTER_INFO = {
    'nodes': CLUSTER_NODES,
    'nve_support': True,
}

SSC_DISK_TYPES = ['FCAL', ['SATA', 'SSD']]

NODE = 'cluster1-01'

COUNTERS_T1 = [
    {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:system',
        'avg_processor_busy': '29078861388',
        'instance-name': 'system',
        'timestamp': '1453573776',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:system',
        'cpu_elapsed_time': '1063283283681',
        'instance-name': 'system',
        'timestamp': '1453573776',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:system',
        'cpu_elapsed_time1': '1063283283681',
        'instance-name': 'system',
        'timestamp': '1453573776',
    }, {
        'cp_phase_times:p2a_snap': '714',
        'cp_phase_times:p4_finish': '14897',
        'cp_phase_times:setup': '581',
        'cp_phase_times:p2a_dlog1': '6019',
        'cp_phase_times:p2a_dlog2': '2328',
        'cp_phase_times:p2v_cont': '2479',
        'cp_phase_times:p2v_volinfo': '1138',
        'cp_phase_times:p2v_bm': '3484',
        'cp_phase_times:p2v_fsinfo': '2031',
        'cp_phase_times:p2a_inofile': '356',
        'cp_phase_times': '581,5007,1840,9832,498,0,839,799,1336,2031,0,377,'
                          '427,1058,354,3484,5135,1460,1138,2479,356,1373'
                          ',6019,9,2328,2257,229,493,1275,0,6059,714,530215,'
                          '21603833,0,0,3286,11075940,22001,14897,36',
        'cp_phase_times:p2v_dlog2': '377',
        'instance-name': 'wafl',
        'cp_phase_times:p3_wait': '0',
        'cp_phase_times:p2a_bm': '6059',
        'cp_phase_times:p1_quota': '498',
        'cp_phase_times:p2v_inofile': '839',
        'cp_phase_times:p2a_refcount': '493',
        'cp_phase_times:p2a_fsinfo': '2257',
        'cp_phase_times:p2a_hyabc': '0',
        'cp_phase_times:p2a_volinfo': '530215',
        'cp_phase_times:pre_p0': '5007',
        'cp_phase_times:p2a_hya': '9',
        'cp_phase_times:p0_snap_del': '1840',
        'cp_phase_times:p2a_ino': '1373',
        'cp_phase_times:p2v_df_scores_sub': '354',
        'cp_phase_times:p2v_ino_pub': '799',
        'cp_phase_times:p2a_ipu_bitmap_grow': '229',
        'cp_phase_times:p2v_refcount': '427',
        'timestamp': '1453573776',
        'cp_phase_times:p2v_dlog1': '0',
        'cp_phase_times:p2_finish': '0',
        'cp_phase_times:p1_clean': '9832',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:wafl',
        'cp_phase_times:p3a_volinfo': '11075940',
        'cp_phase_times:p2a_topaa': '1275',
        'cp_phase_times:p2_flush': '21603833',
        'cp_phase_times:p2v_df_scores': '1460',
        'cp_phase_times:ipu_disk_add': '0',
        'cp_phase_times:p2v_snap': '5135',
        'cp_phase_times:p5_finish': '36',
        'cp_phase_times:p2v_ino_pri': '1336',
        'cp_phase_times:p3v_volinfo': '3286',
        'cp_phase_times:p2v_topaa': '1058',
        'cp_phase_times:p3_finish': '22001',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:wafl',
        'total_cp_msecs': '33309624',
        'instance-name': 'wafl',
        'timestamp': '1453573776',
    }, {
        'domain_busy:kahuna': '2712467226',
        'timestamp': '1453573777',
        'domain_busy:cifs': '434036',
        'domain_busy:raid_exempt': '28',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor0',
        'domain_busy:target': '6460782',
        'domain_busy:nwk_exempt': '20',
        'domain_busy:raid': '722094140',
        'domain_busy:storage': '2253156562',
        'instance-name': 'processor0',
        'domain_busy:cluster': '34',
        'domain_busy:wafl_xcleaner': '51275254',
        'domain_busy:wafl_exempt': '1243553699',
        'domain_busy:protocol': '54',
        'domain_busy': '1028851855595,2712467226,2253156562,5688808118,'
                       '722094140,28,6460782,59,434036,1243553699,51275254,'
                       '61237441,34,54,11,20,5254181873,13656398235,452215',
        'domain_busy:nwk_legacy': '5254181873',
        'domain_busy:dnscache': '59',
        'domain_busy:exempt': '5688808118',
        'domain_busy:hostos': '13656398235',
        'domain_busy:sm_exempt': '61237441',
        'domain_busy:nwk_exclusive': '11',
        'domain_busy:idle': '1028851855595',
        'domain_busy:ssan_exempt': '452215',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor0',
        'processor_elapsed_time': '1063283843318',
        'instance-name': 'processor0',
        'timestamp': '1453573777',
    }, {
        'domain_busy:kahuna': '1978024846',
        'timestamp': '1453573777',
        'domain_busy:cifs': '318584',
        'domain_busy:raid_exempt': '0',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor1',
        'domain_busy:target': '3330956',
        'domain_busy:nwk_exempt': '0',
        'domain_busy:raid': '722235930',
        'domain_busy:storage': '1498890708',
        'instance-name': 'processor1',
        'domain_busy:cluster': '0',
        'domain_busy:wafl_xcleaner': '50122685',
        'domain_busy:wafl_exempt': '1265921369',
        'domain_busy:protocol': '0',
        'domain_busy': '1039557880852,1978024846,1498890708,3734060289,'
                       '722235930,0,3330956,0,318584,1265921369,50122685,'
                       '36417362,0,0,0,0,2815252976,10274810484,393451',
        'domain_busy:nwk_legacy': '2815252976',
        'domain_busy:dnscache': '0',
        'domain_busy:exempt': '3734060289',
        'domain_busy:hostos': '10274810484',
        'domain_busy:sm_exempt': '36417362',
        'domain_busy:nwk_exclusive': '0',
        'domain_busy:idle': '1039557880852',
        'domain_busy:ssan_exempt': '393451',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor1',
        'processor_elapsed_time': '1063283843321',
        'instance-name': 'processor1',
        'timestamp': '1453573777',
    }
]

COUNTERS_T2 = [
    {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:system',
        'avg_processor_busy': '29081228905',
        'instance-name': 'system',
        'timestamp': '1453573834',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:system',
        'cpu_elapsed_time': '1063340792148',
        'instance-name': 'system',
        'timestamp': '1453573834',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:system',
        'cpu_elapsed_time1': '1063340792148',
        'instance-name': 'system',
        'timestamp': '1453573834',
    }, {
        'cp_phase_times:p2a_snap': '714',
        'cp_phase_times:p4_finish': '14897',
        'cp_phase_times:setup': '581',
        'cp_phase_times:p2a_dlog1': '6019',
        'cp_phase_times:p2a_dlog2': '2328',
        'cp_phase_times:p2v_cont': '2479',
        'cp_phase_times:p2v_volinfo': '1138',
        'cp_phase_times:p2v_bm': '3484',
        'cp_phase_times:p2v_fsinfo': '2031',
        'cp_phase_times:p2a_inofile': '356',
        'cp_phase_times': '581,5007,1840,9832,498,0,839,799,1336,2031,0,377,'
                          '427,1058,354,3484,5135,1460,1138,2479,356,1373,'
                          '6019,9,2328,2257,229,493,1275,0,6059,714,530215,'
                          '21604863,0,0,3286,11076392,22001,14897,36',
        'cp_phase_times:p2v_dlog2': '377',
        'instance-name': 'wafl',
        'cp_phase_times:p3_wait': '0',
        'cp_phase_times:p2a_bm': '6059',
        'cp_phase_times:p1_quota': '498',
        'cp_phase_times:p2v_inofile': '839',
        'cp_phase_times:p2a_refcount': '493',
        'cp_phase_times:p2a_fsinfo': '2257',
        'cp_phase_times:p2a_hyabc': '0',
        'cp_phase_times:p2a_volinfo': '530215',
        'cp_phase_times:pre_p0': '5007',
        'cp_phase_times:p2a_hya': '9',
        'cp_phase_times:p0_snap_del': '1840',
        'cp_phase_times:p2a_ino': '1373',
        'cp_phase_times:p2v_df_scores_sub': '354',
        'cp_phase_times:p2v_ino_pub': '799',
        'cp_phase_times:p2a_ipu_bitmap_grow': '229',
        'cp_phase_times:p2v_refcount': '427',
        'timestamp': '1453573834',
        'cp_phase_times:p2v_dlog1': '0',
        'cp_phase_times:p2_finish': '0',
        'cp_phase_times:p1_clean': '9832',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:wafl',
        'cp_phase_times:p3a_volinfo': '11076392',
        'cp_phase_times:p2a_topaa': '1275',
        'cp_phase_times:p2_flush': '21604863',
        'cp_phase_times:p2v_df_scores': '1460',
        'cp_phase_times:ipu_disk_add': '0',
        'cp_phase_times:p2v_snap': '5135',
        'cp_phase_times:p5_finish': '36',
        'cp_phase_times:p2v_ino_pri': '1336',
        'cp_phase_times:p3v_volinfo': '3286',
        'cp_phase_times:p2v_topaa': '1058',
        'cp_phase_times:p3_finish': '22001',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:wafl',
        'total_cp_msecs': '33311106',
        'instance-name': 'wafl',
        'timestamp': '1453573834',
    }, {
        'domain_busy:kahuna': '2712629374',
        'timestamp': '1453573834',
        'domain_busy:cifs': '434036',
        'domain_busy:raid_exempt': '28',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor0',
        'domain_busy:target': '6461082',
        'domain_busy:nwk_exempt': '20',
        'domain_busy:raid': '722136824',
        'domain_busy:storage': '2253260824',
        'instance-name': 'processor0',
        'domain_busy:cluster': '34',
        'domain_busy:wafl_xcleaner': '51277506',
        'domain_busy:wafl_exempt': '1243637154',
        'domain_busy:protocol': '54',
        'domain_busy': '1028906640232,2712629374,2253260824,5689093500,'
                       '722136824,28,6461082,59,434036,1243637154,51277506,'
                       '61240335,34,54,11,20,5254491236,13657992139,452215',
        'domain_busy:nwk_legacy': '5254491236',
        'domain_busy:dnscache': '59',
        'domain_busy:exempt': '5689093500',
        'domain_busy:hostos': '13657992139',
        'domain_busy:sm_exempt': '61240335',
        'domain_busy:nwk_exclusive': '11',
        'domain_busy:idle': '1028906640232',
        'domain_busy:ssan_exempt': '452215',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor0',
        'processor_elapsed_time': '1063341351916',
        'instance-name': 'processor0',
        'timestamp': '1453573834',
    }, {
        'domain_busy:kahuna': '1978217049',
        'timestamp': '1453573834',
        'domain_busy:cifs': '318584',
        'domain_busy:raid_exempt': '0',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor1',
        'domain_busy:target': '3331147',
        'domain_busy:nwk_exempt': '0',
        'domain_busy:raid': '722276805',
        'domain_busy:storage': '1498984059',
        'instance-name': 'processor1',
        'domain_busy:cluster': '0',
        'domain_busy:wafl_xcleaner': '50126176',
        'domain_busy:wafl_exempt': '1266039846',
        'domain_busy:protocol': '0',
        'domain_busy': '1039613222253,1978217049,1498984059,3734279672,'
                       '722276805,0,3331147,0,318584,1266039846,50126176,'
                       '36419297,0,0,0,0,2815435865,10276068104,393451',
        'domain_busy:nwk_legacy': '2815435865',
        'domain_busy:dnscache': '0',
        'domain_busy:exempt': '3734279672',
        'domain_busy:hostos': '10276068104',
        'domain_busy:sm_exempt': '36419297',
        'domain_busy:nwk_exclusive': '0',
        'domain_busy:idle': '1039613222253',
        'domain_busy:ssan_exempt': '393451',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor1',
        'processor_elapsed_time': '1063341351919',
        'instance-name': 'processor1',
        'timestamp': '1453573834',
    },
]

SYSTEM_INSTANCE_UUIDS = ['cluster1-01:kernel:system']
SYSTEM_INSTANCE_NAMES = ['system']

SYSTEM_COUNTERS = [
    {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:system',
        'avg_processor_busy': '27877641199',
        'instance-name': 'system',
        'timestamp': '1453524928',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:system',
        'cpu_elapsed_time': '1014438541279',
        'instance-name': 'system',
        'timestamp': '1453524928',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:system',
        'cpu_elapsed_time1': '1014438541279',
        'instance-name': 'system',
        'timestamp': '1453524928',
    },
]


WAFL_INSTANCE_UUIDS = ['cluster1-01:kernel:wafl']
WAFL_INSTANCE_NAMES = ['wafl']

WAFL_COUNTERS = [
    {
        'cp_phase_times': '563,4844,1731,9676,469,0,821,763,1282,1937,0,359,'
                          '418,1048,344,3344,4867,1397,1101,2380,356,1318,'
                          '5954,9,2236,2190,228,476,1221,0,5838,696,515588,'
                          '20542954,0,0,3122,10567367,20696,13982,36',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:wafl',
        'instance-name': 'wafl',
        'timestamp': '1453523339',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:wafl',
        'total_cp_msecs': '31721222',
        'instance-name': 'wafl',
        'timestamp': '1453523339',
    },
]

WAFL_CP_PHASE_TIMES_COUNTER_INFO = {
    'labels': [
        'SETUP', 'PRE_P0', 'P0_SNAP_DEL', 'P1_CLEAN', 'P1_QUOTA',
        'IPU_DISK_ADD', 'P2V_INOFILE', 'P2V_INO_PUB', 'P2V_INO_PRI',
        'P2V_FSINFO', 'P2V_DLOG1', 'P2V_DLOG2', 'P2V_REFCOUNT',
        'P2V_TOPAA', 'P2V_DF_SCORES_SUB', 'P2V_BM', 'P2V_SNAP',
        'P2V_DF_SCORES', 'P2V_VOLINFO', 'P2V_CONT', 'P2A_INOFILE',
        'P2A_INO', 'P2A_DLOG1', 'P2A_HYA', 'P2A_DLOG2', 'P2A_FSINFO',
        'P2A_IPU_BITMAP_GROW', 'P2A_REFCOUNT', 'P2A_TOPAA',
        'P2A_HYABC', 'P2A_BM', 'P2A_SNAP', 'P2A_VOLINFO', 'P2_FLUSH',
        'P2_FINISH', 'P3_WAIT', 'P3V_VOLINFO', 'P3A_VOLINFO',
        'P3_FINISH', 'P4_FINISH', 'P5_FINISH',
    ],
    'name': 'cp_phase_times',
}

EXPANDED_WAFL_COUNTERS = [
    {
        'cp_phase_times:p2a_snap': '696',
        'cp_phase_times:p4_finish': '13982',
        'cp_phase_times:setup': '563',
        'cp_phase_times:p2a_dlog1': '5954',
        'cp_phase_times:p2a_dlog2': '2236',
        'cp_phase_times:p2v_cont': '2380',
        'cp_phase_times:p2v_volinfo': '1101',
        'cp_phase_times:p2v_bm': '3344',
        'cp_phase_times:p2v_fsinfo': '1937',
        'cp_phase_times:p2a_inofile': '356',
        'cp_phase_times': '563,4844,1731,9676,469,0,821,763,1282,1937,0,359,'
                          '418,1048,344,3344,4867,1397,1101,2380,356,1318,'
                          '5954,9,2236,2190,228,476,1221,0,5838,696,515588,'
                          '20542954,0,0,3122,10567367,20696,13982,36',
        'cp_phase_times:p2v_dlog2': '359',
        'instance-name': 'wafl',
        'cp_phase_times:p3_wait': '0',
        'cp_phase_times:p2a_bm': '5838',
        'cp_phase_times:p1_quota': '469',
        'cp_phase_times:p2v_inofile': '821',
        'cp_phase_times:p2a_refcount': '476',
        'cp_phase_times:p2a_fsinfo': '2190',
        'cp_phase_times:p2a_hyabc': '0',
        'cp_phase_times:p2a_volinfo': '515588',
        'cp_phase_times:pre_p0': '4844',
        'cp_phase_times:p2a_hya': '9',
        'cp_phase_times:p0_snap_del': '1731',
        'cp_phase_times:p2a_ino': '1318',
        'cp_phase_times:p2v_df_scores_sub': '344',
        'cp_phase_times:p2v_ino_pub': '763',
        'cp_phase_times:p2a_ipu_bitmap_grow': '228',
        'cp_phase_times:p2v_refcount': '418',
        'timestamp': '1453523339',
        'cp_phase_times:p2v_dlog1': '0',
        'cp_phase_times:p2_finish': '0',
        'cp_phase_times:p1_clean': '9676',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:wafl',
        'cp_phase_times:p3a_volinfo': '10567367',
        'cp_phase_times:p2a_topaa': '1221',
        'cp_phase_times:p2_flush': '20542954',
        'cp_phase_times:p2v_df_scores': '1397',
        'cp_phase_times:ipu_disk_add': '0',
        'cp_phase_times:p2v_snap': '4867',
        'cp_phase_times:p5_finish': '36',
        'cp_phase_times:p2v_ino_pri': '1282',
        'cp_phase_times:p3v_volinfo': '3122',
        'cp_phase_times:p2v_topaa': '1048',
        'cp_phase_times:p3_finish': '20696',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:wafl',
        'total_cp_msecs': '31721222',
        'instance-name': 'wafl',
        'timestamp': '1453523339',
    },
]

PROCESSOR_INSTANCE_UUIDS = [
    'cluster1-01:kernel:processor0',
    'cluster1-01:kernel:processor1',
]
PROCESSOR_INSTANCE_NAMES = ['processor0', 'processor1']

PROCESSOR_COUNTERS = [
    {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor0',
        'domain_busy': '980648687811,2597164534,2155400686,5443901498,'
                       '690280568,28,6180773,59,413895,1190100947,48989575,'
                       '58549809,34,54,11,20,5024141791,13136260754,452215',
        'instance-name': 'processor0',
        'timestamp': '1453524150',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor0',
        'processor_elapsed_time': '1013660714257',
        'instance-name': 'processor0',
        'timestamp': '1453524150',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor1',
        'domain_busy': '990957980543,1891766637,1433411516,3572427934,'
                       '691372324,0,3188648,0,305947,1211235777,47954620,'
                       '34832715,0,0,0,0,2692084482,9834648927,393451',
        'instance-name': 'processor1',
        'timestamp': '1453524150',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor1',
        'processor_elapsed_time': '1013660714261',
        'instance-name': 'processor1',
        'timestamp': '1453524150',
    },
]

PROCESSOR_DOMAIN_BUSY_COUNTER_INFO = {
    'labels': [
        'idle', 'kahuna', 'storage', 'exempt', 'raid', 'raid_exempt',
        'target', 'dnscache', 'cifs', 'wafl_exempt', 'wafl_xcleaner',
        'sm_exempt', 'cluster', 'protocol', 'nwk_exclusive', 'nwk_exempt',
        'nwk_legacy', 'hostOS', 'ssan_exempt',
    ],
    'name': 'domain_busy',
}

EXPANDED_PROCESSOR_COUNTERS = [
    {
        'domain_busy:kahuna': '2597164534',
        'timestamp': '1453524150',
        'domain_busy:cifs': '413895',
        'domain_busy:raid_exempt': '28',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor0',
        'domain_busy:target': '6180773',
        'domain_busy:nwk_exempt': '20',
        'domain_busy:raid': '690280568',
        'domain_busy:storage': '2155400686',
        'instance-name': 'processor0',
        'domain_busy:cluster': '34',
        'domain_busy:wafl_xcleaner': '48989575',
        'domain_busy:wafl_exempt': '1190100947',
        'domain_busy:protocol': '54',
        'domain_busy': '980648687811,2597164534,2155400686,5443901498,'
                       '690280568,28,6180773,59,413895,1190100947,48989575,'
                       '58549809,34,54,11,20,5024141791,13136260754,452215',
        'domain_busy:nwk_legacy': '5024141791',
        'domain_busy:dnscache': '59',
        'domain_busy:exempt': '5443901498',
        'domain_busy:hostos': '13136260754',
        'domain_busy:sm_exempt': '58549809',
        'domain_busy:nwk_exclusive': '11',
        'domain_busy:idle': '980648687811',
        'domain_busy:ssan_exempt': '452215',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor0',
        'processor_elapsed_time': '1013660714257',
        'instance-name': 'processor0',
        'timestamp': '1453524150',
    }, {
        'domain_busy:kahuna': '1891766637',
        'timestamp': '1453524150',
        'domain_busy:cifs': '305947',
        'domain_busy:raid_exempt': '0',
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor1',
        'domain_busy:target': '3188648',
        'domain_busy:nwk_exempt': '0',
        'domain_busy:raid': '691372324',
        'domain_busy:storage': '1433411516',
        'instance-name': 'processor1',
        'domain_busy:cluster': '0',
        'domain_busy:wafl_xcleaner': '47954620',
        'domain_busy:wafl_exempt': '1211235777',
        'domain_busy:protocol': '0',
        'domain_busy': '990957980543,1891766637,1433411516,3572427934,'
                       '691372324,0,3188648,0,305947,1211235777,47954620,'
                       '34832715,0,0,0,0,2692084482,9834648927,393451',
        'domain_busy:nwk_legacy': '2692084482',
        'domain_busy:dnscache': '0',
        'domain_busy:exempt': '3572427934',
        'domain_busy:hostos': '9834648927',
        'domain_busy:sm_exempt': '34832715',
        'domain_busy:nwk_exclusive': '0',
        'domain_busy:idle': '990957980543',
        'domain_busy:ssan_exempt': '393451',
    }, {
        'node-name': 'cluster1-01',
        'instance-uuid': 'cluster1-01:kernel:processor1',
        'processor_elapsed_time': '1013660714261',
        'instance-name': 'processor1',
        'timestamp': '1453524150',
    },
]


def get_config_cmode():
    config = na_fakes.create_configuration_cmode()
    config.local_conf.set_override('share_backend_name', BACKEND_NAME)
    config.reserved_share_percentage = 5
    config.netapp_login = CLIENT_KWARGS['username']
    config.netapp_password = CLIENT_KWARGS['password']
    config.netapp_server_hostname = CLIENT_KWARGS['hostname']
    config.netapp_transport_type = CLIENT_KWARGS['transport_type']
    config.netapp_server_port = CLIENT_KWARGS['port']
    config.netapp_volume_name_template = VOLUME_NAME_TEMPLATE
    config.netapp_aggregate_name_search_pattern = AGGREGATE_NAME_SEARCH_PATTERN
    config.netapp_vserver_name_template = VSERVER_NAME_TEMPLATE
    config.netapp_root_volume_aggregate = ROOT_VOLUME_AGGREGATE
    config.netapp_root_volume = ROOT_VOLUME
    config.netapp_lif_name_template = LIF_NAME_TEMPLATE
    config.netapp_volume_snapshot_reserve_percent = 8
    config.netapp_vserver = VSERVER1
    return config


def get_network_info(user_network_allocation, admin_network_allocation):
    net_info = copy.deepcopy(NETWORK_INFO)
    net_info['network_allocations'] = user_network_allocation
    net_info['admin_network_allocations'] = admin_network_allocation

    return net_info
