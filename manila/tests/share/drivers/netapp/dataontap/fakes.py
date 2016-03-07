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

CLIENT_KWARGS = {
    'username': 'admin',
    'trace': False,
    'hostname': '127.0.0.1',
    'vserver': None,
    'transport_type': 'https',
    'password': 'pass',
    'port': '443'
}

SHARE = {
    'id': SHARE_ID,
    'host': '%(host)s@%(backend)s#%(pool)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME, 'pool': POOL_NAME},
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
}

FLEXVOL_TO_MANAGE = {
    'aggregate': POOL_NAME,
    'junction-path': '/%s' % FLEXVOL_NAME,
    'name': FLEXVOL_NAME,
    'type': 'rw',
    'style': 'flex',
    'size': '1610612736',  # rounds down to 1 GB
}

EXTRA_SPEC = {
    'netapp:thin_provisioned': 'true',
    'netapp:snapshot_policy': 'default',
    'netapp:language': 'en-US',
    'netapp:dedup': 'True',
    'netapp:compression': 'false',
    'netapp:max_files': 5000,
    'netapp_disk_type': 'FCAL',
    'netapp_raid_type': 'raid4',
}

PROVISIONING_OPTIONS = {
    'thin_provisioned': True,
    'snapshot_policy': 'default',
    'language': 'en-US',
    'dedup_enabled': True,
    'compression_enabled': False,
    'max_files': 5000,
}

PROVISIONING_OPTIONS_BOOLEAN = {
    'thin_provisioned': True,
    'dedup_enabled': False,
    'compression_enabled': False,
}

PROVISIONING_OPTIONS_BOOLEAN_THIN_PROVISIONED_TRUE = {
    'thin_provisioned': True,
    'snapshot_policy': None,
    'language': None,
    'dedup_enabled': False,
    'compression_enabled': False,
    'max_files': None,
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
    },
    {
        'id': '7eabdeed-bad2-46ea-bd0f-a33884c869e0',
        'ip_address': '10.10.10.20',
        'cidr': '10.10.10.0/24',
        'segmentation_id': '1000',
        'network_type': 'vlan',
        'label': 'user',
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
    },
]

NETWORK_INFO = {
    'server_id': '56aafd02-4d44-43d7-b784-57fc88167224',
    'security_services': ['fake_ldap', 'fake_kerberos', 'fake_ad', ],
    'network_allocations': USER_NETWORK_ALLOCATIONS,
    'admin_network_allocations': ADMIN_NETWORK_ALLOCATIONS,
    'neutron_subnet_id': '62bf1c2c-18eb-421b-8983-48a6d39aafe0',
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

CDOT_SNAPSHOT = {
    'name': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'busy': False,
    'owners': set(),
}

CDOT_SNAPSHOT_BUSY_VOLUME_CLONE = {
    'name': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'busy': True,
    'owners': {'volume clone'},
}

CDOT_SNAPSHOT_BUSY_SNAPMIRROR = {
    'name': SNAPSHOT_NAME,
    'volume': SHARE_NAME,
    'busy': True,
    'owners': {'snapmirror'},
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
    'source_cgsnapshot_member_id': None,
}

SHARE_FOR_CG2 = {
    'id': SHARE_ID2,
    'host': '%(host)s@%(backend)s#%(pool)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME, 'pool': POOL_NAME},
    'name': 'share_2',
    'share_proto': 'NFS',
    'source_cgsnapshot_member_id': None,
}

# Clone dest of SHARE_FOR_CG1
SHARE_FOR_CG3 = {
    'id': SHARE_ID3,
    'host': '%(host)s@%(backend)s#%(pool)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME, 'pool': POOL_NAME},
    'name': 'share3',
    'share_proto': 'NFS',
    'source_cgsnapshot_member_id': CG_SNAPSHOT_MEMBER_ID1,
}

# Clone dest of SHARE_FOR_CG2
SHARE_FOR_CG4 = {
    'id': SHARE_ID4,
    'host': '%(host)s@%(backend)s#%(pool)s' % {
        'host': HOST_NAME, 'backend': BACKEND_NAME, 'pool': POOL_NAME},
    'name': 'share4',
    'share_proto': 'NFS',
    'source_cgsnapshot_member_id': CG_SNAPSHOT_MEMBER_ID2,
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
}

CG_SNAPSHOT_MEMBER_2 = {
    'cgsnapshot_id': CG_SNAPSHOT_ID,
    'id': CG_SNAPSHOT_MEMBER_ID2,
    'share_id': SHARE_ID2,
    'share_proto': 'NFS',
}

CG_SNAPSHOT = {
    'cgsnapshot_members': [CG_SNAPSHOT_MEMBER_1, CG_SNAPSHOT_MEMBER_2],
    'consistency_group': CONSISTENCY_GROUP,
    'consistency_group_id': CONSISTENCY_GROUP_ID,
    'id': CG_SNAPSHOT_ID,
    'project_id': TENANT_ID,
}

COLLATED_CGSNAPSHOT_INFO = [
    {
        'share': SHARE_FOR_CG3,
        'snapshot': {
            'share_id': SHARE_ID,
            'id': CG_SNAPSHOT_ID
        }
    },
    {
        'share': SHARE_FOR_CG4,
        'snapshot': {
            'share_id': SHARE_ID2,
            'id': CG_SNAPSHOT_ID
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

EMS_MESSAGE = {
    'computer-name': 'fake_host',
    'event-id': '0',
    'event-source': 'fake_driver',
    'app-version': 'fake_app_version',
    'category': 'fake_category',
    'event-description': 'fake_description',
    'log-level': '6',
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
        'netapp_disk_type': 'FCAL'
    },
    AGGREGATES[1]: {
        'netapp_raid_type': 'raid_dp',
        'netapp_disk_type': 'SSD'
    }
}

POOLS = [
    {'pool_name': AGGREGATES[0],
     'total_capacity_gb': 3.3,
     'free_capacity_gb': 1.1,
     'allocated_capacity_gb': 2.2,
     'qos': 'False',
     'reserved_percentage': 0,
     'dedupe': [True, False],
     'compression': [True, False],
     'thin_provisioning': [True, False],
     'netapp_raid_type': 'raid4',
     'netapp_disk_type': 'FCAL'
     },
    {'pool_name': AGGREGATES[1],
     'total_capacity_gb': 6.0,
     'free_capacity_gb': 2.0,
     'allocated_capacity_gb': 4.0,
     'qos': 'False',
     'reserved_percentage': 0,
     'dedupe': [True, False],
     'compression': [True, False],
     'thin_provisioning': [True, False],
     'netapp_raid_type': 'raid_dp',
     'netapp_disk_type': 'SSD'
     },
]

POOLS_VSERVER_CREDS = [
    {'pool_name': AGGREGATES[0],
     'total_capacity_gb': 'unknown',
     'free_capacity_gb': 1.1,
     'allocated_capacity_gb': 0.0,
     'qos': 'False',
     'reserved_percentage': 0,
     'dedupe': [True, False],
     'compression': [True, False],
     'thin_provisioning': [True, False],
     'netapp_raid_type': 'raid4',
     'netapp_disk_type': 'FCAL'
     },
    {'pool_name': AGGREGATES[1],
     'total_capacity_gb': 'unknown',
     'free_capacity_gb': 2.0,
     'allocated_capacity_gb': 0.0,
     'qos': 'False',
     'reserved_percentage': 0,
     'dedupe': [True, False],
     'compression': [True, False],
     'thin_provisioning': [True, False],
     'netapp_raid_type': 'raid_dp',
     'netapp_disk_type': 'SSD'
     },
]

SSC_RAID_TYPES = {
    AGGREGATES[0]: 'raid4',
    AGGREGATES[1]: 'raid_dp'
}

SSC_DISK_TYPES = {
    AGGREGATES[0]: 'FCAL',
    AGGREGATES[1]: 'SSD'
}


def get_config_cmode():
    config = na_fakes.create_configuration_cmode()
    config.local_conf.set_override('share_backend_name', BACKEND_NAME)
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
