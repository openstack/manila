# Copyright 2015 Hewlett Packard Development Company, L.P.
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
PASSWORD = 'PASSWORD_0'
SAN_LOGIN = 'testlogin4san'
SAN_PASSWORD = 'testpassword4san'
API_URL = 'https://1.2.3.4:8080/api/v1'
TIMEOUT = 60
PORT = 22

# Constants to use with Mock and expect in results
EXPECTED_IP_10203040 = '10.20.30.40'
EXPECTED_IP_1234 = '1.2.3.4'
EXPECTED_IP_127 = '127.0.0.1'
EXPECTED_SHARE_ID = 'osf-share-id'
EXPECTED_SHARE_NAME = 'share-name'
EXPECTED_SHARE_PATH = '/share/path'
EXPECTED_SIZE_1 = 1
EXPECTED_SIZE_2 = 2
EXPECTED_SNAP_NAME = 'osf-snap-name'
EXPECTED_SNAP_ID = 'osf-snap-id'
EXPECTED_STATS = {'test': 'stats'}
EXPECTED_FPG = 'FPG_1'
EXPECTED_FSTORE = 'osf-test_fstore'
EXPECTED_VFS = 'test_vfs'
EXPECTED_HP_DEBUG = True

NFS_SHARE_INFO = {
    'id': EXPECTED_SHARE_ID,
    'share_proto': NFS,
}

ACCESS_INFO = {
    'access_type': IP,
    'access_to': EXPECTED_IP_1234,
}

SNAPSHOT_INFO = {
    'name': EXPECTED_SNAP_NAME,
    'id': EXPECTED_SNAP_ID,
    'share': {'id': EXPECTED_SHARE_ID},
}
