# Copyright 2015 Hewlett Packard Enterprise Development LP
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
CIFS = 'CIFS'
SMB_LOWER = 'smb'
NFS = 'NFS'
NFS_LOWER = 'nfs'
IP = 'ip'
USER = 'user'
USERNAME = 'USERNAME_0'
ADD_USERNAME = '+USERNAME_0:fullcontrol'
DROP_USERNAME = '-USERNAME_0:fullcontrol'
PASSWORD = 'PASSWORD_0'
READ_WRITE = 'rw'
READ_ONLY = 'ro'
SAN_LOGIN = 'testlogin4san'
SAN_PASSWORD = 'testpassword4san'
API_URL = 'https://1.2.3.4:8080/api/v1'
TIMEOUT = 60
PORT = 22
SHARE_TYPE_ID = 123456789
CIDR_PREFIX = '24'

# Constants to use with Mock and expect in results
EXPECTED_IP_10203040 = '10.20.30.40'
EXPECTED_IP_10203041 = '10.20.30.41'
EXPECTED_IP_1234 = '1.2.3.4'
EXPECTED_MY_IP = '9.8.7.6'
EXPECTED_IP_127 = '127.0.0.1'
EXPECTED_IP_127_2 = '127.0.0.2'
EXPECTED_ACCESS_LEVEL = 'foo_access'
EXPECTED_SUBNET = '255.255.255.0'  # based on CIDR_PREFIX above
EXPECTED_VLAN_TYPE = 'vlan'
EXPECTED_VXLAN_TYPE = 'vxlan'
EXPECTED_VLAN_TAG = '101'
EXPECTED_SERVER_ID = '1a1a1a1a-2b2b-3c3c-4d4d-5e5e5e5e5e5e'
EXPECTED_PROJECT_ID = 'osf-nfs-project-id'
SHARE_ID = 'share-id'
EXPECTED_SHARE_ID = 'osf-share-id'
EXPECTED_SHARE_ID_RO = 'osf-ro-share-id'
EXPECTED_SHARE_NAME = 'share-name'
EXPECTED_NET_NAME = 'testnet'
EXPECTED_FPG = 'pool'
EXPECTED_HOST = 'hostname@backend#' + EXPECTED_FPG
UNEXPECTED_FPG = 'not_a_pool'
UNEXPECTED_HOST = 'hostname@backend#' + UNEXPECTED_FPG
HOST_WITHOUT_POOL_1 = 'hostname@backend'
HOST_WITHOUT_POOL_2 = 'hostname@backend#'
EXPECTED_SHARE_PATH = '/anyfpg/anyvfs/anyfstore'
EXPECTED_SIZE_1 = 1
EXPECTED_SIZE_2 = 2
EXPECTED_SNAP_NAME = 'osf-snap-name'
EXPECTED_SNAP_ID = 'osf-snap-id'
EXPECTED_STATS = {'test': 'stats'}
EXPECTED_FPG_CONF = [{EXPECTED_FPG: [EXPECTED_IP_10203040]}]
EXPECTED_FSTORE = EXPECTED_PROJECT_ID
EXPECTED_VFS = 'test_vfs'
EXPECTED_GET_VFS = {'vfsname': EXPECTED_VFS,
                    'vfsip': {'address': [EXPECTED_IP_10203040]}}
EXPECTED_GET_VFS_MULTIPLES = {
    'vfsname': EXPECTED_VFS,
    'vfsip': {'address': [EXPECTED_IP_10203041, EXPECTED_IP_10203040]}}

EXPECTED_CLIENT_GET_VFS_MEMBERS_MULTI = {
    'fspname': EXPECTED_VFS,
    'vfsip': [
        {'networkName': EXPECTED_NET_NAME,
         'fspool': EXPECTED_VFS,
         'address': EXPECTED_IP_10203040,
         'prefixLen': EXPECTED_SUBNET,
         'vfs': EXPECTED_VFS,
         'vlanTag': EXPECTED_VLAN_TAG,
         },
        {'networkName': EXPECTED_NET_NAME,
         'fspool': EXPECTED_VFS,
         'address': EXPECTED_IP_10203041,
         'prefixLen': EXPECTED_SUBNET,
         'vfs': EXPECTED_VFS,
         'vlanTag': EXPECTED_VLAN_TAG,
         },
    ],
    'vfsname': EXPECTED_VFS,
    }
EXPECTED_MEDIATOR_GET_VFS_RET_VAL_MULTI = {
    'fspname': EXPECTED_VFS,
    'vfsip': {
        'networkName': EXPECTED_NET_NAME,
        'fspool': EXPECTED_VFS,
        'address': [
            EXPECTED_IP_10203040,
            EXPECTED_IP_10203041,
        ],
        'prefixLen': EXPECTED_SUBNET,
        'vfs': EXPECTED_VFS,
        'vlanTag': EXPECTED_VLAN_TAG
    },
    'vfsname': EXPECTED_VFS,
    }

EXPECTED_CLIENT_GET_VFS_MEMBERS = {
    'fspname': EXPECTED_VFS,
    'vfsip': {
        'networkName': EXPECTED_NET_NAME,
        'fspool': EXPECTED_VFS,
        'address': EXPECTED_IP_10203040,
        'prefixLen': EXPECTED_SUBNET,
        'vfs': EXPECTED_VFS,
        'vlanTag': EXPECTED_VLAN_TAG,
    },
    'vfsname': EXPECTED_VFS,
    }
EXPECTED_MEDIATOR_GET_VFS_RET_VAL = {
    'fspname': EXPECTED_VFS,
    'vfsip': {
        'networkName': EXPECTED_NET_NAME,
        'fspool': EXPECTED_VFS,
        'address': [EXPECTED_IP_10203040],
        'prefixLen': EXPECTED_SUBNET,
        'vfs': EXPECTED_VFS,
        'vlanTag': EXPECTED_VLAN_TAG,
    },
    'vfsname': EXPECTED_VFS,
    }
EXPECTED_CLIENT_GET_VFS_RETURN_VALUE = {
    'total': 1,
    'members': [EXPECTED_CLIENT_GET_VFS_MEMBERS],
    }
EXPECTED_CLIENT_GET_VFS_RETURN_VALUE_MULTI = {
    'total': 1,
    'members': [EXPECTED_CLIENT_GET_VFS_MEMBERS_MULTI],
    }
EXPECTED_FPG_MAP = {EXPECTED_FPG: {EXPECTED_VFS: [EXPECTED_IP_10203040]}}
EXPECTED_FPG_MAP_MULTI_VFS = {EXPECTED_FPG: {
    EXPECTED_VFS: [EXPECTED_IP_10203041, EXPECTED_IP_10203040]}}
EXPECTED_SHARE_IP = '10.50.3.8'
EXPECTED_HPE_DEBUG = True
EXPECTED_COMMENT = "OpenStack Manila - foo-comment"
EXPECTED_EXTRA_SPECS = {}
EXPECTED_LOCATION = ':'.join((EXPECTED_IP_1234, EXPECTED_SHARE_PATH))
EXPECTED_SUPER_SHARE = 'OPENSTACK_SUPER_SHARE'
EXPECTED_SUPER_SHARE_COMMENT = ('OpenStack super share used to delete nested '
                                'shares.')
EXPECTED_CIFS_DOMAIN = 'LOCAL_CLUSTER'
EXPECTED_MOUNT_PATH = '/mnt/'

SHARE_SERVER = {
    'backend_details': {
        'ip': EXPECTED_IP_10203040,
        'fpg': EXPECTED_FPG,
        'vfs': EXPECTED_VFS,
        },
}

# Access rules. Allow for overwrites.
ACCESS_RULE_NFS = {
    'access_type': IP,
    'access_to': EXPECTED_IP_1234,
    'access_level': READ_WRITE,
}

ACCESS_RULE_CIFS = {
    'access_type': USER,
    'access_to': USERNAME,
    'access_level': READ_WRITE,
}

ADD_RULE_BAD_TYPE = {
    'access_type': 'unsupported_other_type',
    'access_to': USERNAME,
    'access_level': READ_WRITE,
}

ADD_RULE_IP = {
    'access_type': IP,
    'access_to': EXPECTED_IP_1234,
    'access_level': READ_WRITE,
}

ADD_RULE_IP_RO = {
    'access_type': IP,
    'access_to': EXPECTED_IP_1234,
    'access_level': READ_ONLY,
}

ADD_RULE_USER = {
    'access_type': USER,
    'access_to': USERNAME,
    'access_level': READ_WRITE,
}

DELETE_RULE_IP = {
    'access_type': IP,
    'access_to': EXPECTED_IP_1234,
    'access_level': READ_WRITE,
}

DELETE_RULE_USER = {
    'access_type': USER,
    'access_to': USERNAME,
    'access_level': READ_WRITE,
}

DELETE_RULE_IP_RO = {
    'access_type': IP,
    'access_to': EXPECTED_IP_1234,
    'access_level': READ_ONLY,
}

GET_FSQUOTA = {'message': None,
               'total': 1,
               'members': [{'hardBlock': '1024', 'softBlock': '1024'}]}

EXPECTED_FSIP = {
    'fspool': EXPECTED_FPG,
    'vfs': EXPECTED_VFS,
    'address': EXPECTED_IP_1234,
    'prefixLen': EXPECTED_SUBNET,
    'vlanTag': EXPECTED_VLAN_TAG,
}

OTHER_FSIP = {
    'fspool': EXPECTED_FPG,
    'vfs': EXPECTED_VFS,
    'address': '9.9.9.9',
    'prefixLen': EXPECTED_SUBNET,
    'vlanTag': EXPECTED_VLAN_TAG,
}

NFS_SHARE_INFO = {
    'project_id': EXPECTED_PROJECT_ID,
    'id': EXPECTED_SHARE_ID,
    'share_proto': NFS,
    'export_location': EXPECTED_LOCATION,
    'size': 1234,
    'host': EXPECTED_HOST,
}

SNAPSHOT_INFO = {
    'name': EXPECTED_SNAP_NAME,
    'id': EXPECTED_SNAP_ID,
    'share': {
        'project_id': EXPECTED_PROJECT_ID,
        'id': EXPECTED_SHARE_ID,
        'share_proto': NFS,
        'export_location': EXPECTED_LOCATION,
        'host': EXPECTED_HOST,
    },
}

SNAPSHOT_INSTANCE = {
    'name': EXPECTED_SNAP_NAME,
    'id': EXPECTED_SNAP_ID,
    'share_id': EXPECTED_SHARE_ID,
    'share_proto': NFS,
}


class FakeException(Exception):
    pass

FAKE_EXCEPTION = FakeException("Fake exception for testing.")
