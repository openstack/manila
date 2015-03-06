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
SHARE_NAME = 'fake_share'
SHARE_SIZE = 10
TENANT_ID = '24cb2448-13d8-4f41-afd9-eff5c4fd2a57'
SHARE_ID = '7cf7c200-d3af-4e05-b87e-9167c95dfcad'
PARENT_SHARE_ID = '585c3935-2aa9-437c-8bad-5abae1076555'
SNAPSHOT_ID = 'de4c9050-e2f9-4ce1-ade4-5ed0c9f26451'
FREE_CAPACITY = 10000000000
TOTAL_CAPACITY = 20000000000
AGGREGATES = ('manila_aggr_1', 'manila_aggr_2')
ROOT_VOLUME_AGGREGATE = 'manila1'
ROOT_VOLUME = 'root'
CLUSTER_NODES = ('cluster1_01', 'cluster1_02')
NODE_DATA_PORT = 'e0c'
LIF_NAME_TEMPLATE = 'os_%(net_allocation_id)s'
SHARE_TYPE_ID = '26e89a5b-960b-46bb-a8cf-0778e653098f'
SHARE_TYPE_NAME = 'fake_share_type'

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
    'share_network_id': '5dfe0898-e2a1-4740-9177-81c7d26713b0',
    'share_server_id': '7e6a2cc8-871f-4b1d-8364-5aad0f98da86',
    'network_info': {
        'network_allocations': [{'ip_address': 'ip'}]
    }
}

EXTRA_SPEC = {
    'netapp:thin_provisioned': 'true',
}

PROVISIONING_OPTIONS = {
    'thin_provisioned': True,
}

SHORT_EXTRA_SPEC = {
    'netapp:thin_provisioned': 'true',
}

INVALID_EXTRA_SPEC = {
    'netapp:thin_provisioned': 'ture',
}


EMPTY_EXTRA_SPEC = {}

SHARE_TYPE = {
    'id': SHARE_TYPE_ID,
    'name': SHARE_TYPE_NAME,
    'extra_specs': EXTRA_SPEC
}

EXTRA_SPEC_SHARE = copy.deepcopy(SHARE)
EXTRA_SPEC_SHARE['share_type_id'] = SHARE_TYPE_ID

NETWORK_INFO = {
    'server_id': '56aafd02-4d44-43d7-b784-57fc88167224',
    'cidr': '10.0.0.0/24',
    'security_services': ['fake_ldap', 'fake_kerberos', 'fake_ad', ],
    'segmentation_id': '1000',
    'network_allocations': [
        {'id': '132dbb10-9a36-46f2-8d89-3d909830c356',
         'ip_address': '10.10.10.10'},
        {'id': '7eabdeed-bad2-46ea-bd0f-a33884c869e0',
         'ip_address': '10.10.10.20'}
    ]
}
NETWORK_INFO_NETMASK = '255.255.255.0'

SHARE_SERVER = {
    'backend_details': {
        'vserver_name': VSERVER1
    }
}

SNAPSHOT = {
    'id': SNAPSHOT_ID,
    'project_id': TENANT_ID,
    'share_id': PARENT_SHARE_ID
}

LIF_NAMES = []
LIF_ADDRESSES = ('10.10.10.10', '10.10.10.20')
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
    return config
