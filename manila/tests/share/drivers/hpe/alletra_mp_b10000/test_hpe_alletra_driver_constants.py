# Copyright (c) 2025 Hewlett Packard Enterprise Development LP
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


WSAPI_URL = 'https://1.2.3.4:8080/api/v3'
USERNAME = 'username1'
PASSWORD = 'password1'
SHARE_BACKEND_NAME = 'backend1'

# Backend resource naming prefixes
BE_FILESYSTEM_PREFIX = 'manilafs-'
BE_SHARESETTING_PREFIX = 'manilass-'

# do_setup test constants
EXPECTED_SYSTEMS = {'version': '10.5.0'}
EXPECTED_OSINFO = {'be_is_fileservice_supported': True}
EXPECTED_FILESERVICE = {
    'be_is_fileservice_enabled': True,
    'be_total_capacity': 102400,  # 100GB in MiB
    'be_used_capacity': 20480,    # 20GB in MiB
    'be_available_capacity': 81920  # 80GB in MiB
}

# create_share test constants
EXPECTED_SHARE_ID = 'a1b2c3d4-e5f6-4789-a012-3456789abcde'
EXPECTED_SHARE_NAME = 'share-a1b2c3d4-e5f6-4789-a012-3456789abcde'
EXPECTED_SHARE_SIZE = 2  # GB
EXPECTED_PROJECT_ID = 'project-123456'
EXPECTED_SHARE_PROTOCOL = 'NFS'

EXPECTED_BE_SHARE_ID = 'bd83b9188305995aa1e52f373ef5b6bc'
EXPECTED_BE_SHARE_NAME = EXPECTED_SHARE_NAME
EXPECTED_BE_FILESYSTEM_NAME = BE_FILESYSTEM_PREFIX + EXPECTED_SHARE_ID
EXPECTED_BE_SHARESETTING_NAME = BE_SHARESETTING_PREFIX + EXPECTED_SHARE_ID
EXPECTED_HOST_IP = '192.168.100.50'
EXPECTED_MOUNT_PATH = (
    '/file/' + EXPECTED_BE_FILESYSTEM_NAME + '/' + EXPECTED_SHARE_NAME
)

EXPECTED_EXTRA_SPECS = {}

SHARE_INFO = {
    'id': EXPECTED_SHARE_ID,
    'display_name': EXPECTED_SHARE_NAME,
    'project_id': EXPECTED_PROJECT_ID,
    'share_proto': EXPECTED_SHARE_PROTOCOL,
    'size': EXPECTED_SHARE_SIZE,
}

BACKEND_FILESHARE = {
    'be_uid': EXPECTED_BE_SHARE_ID,
    'be_fileshare_name': EXPECTED_BE_SHARE_NAME,
    'be_filesystem_name': EXPECTED_BE_FILESYSTEM_NAME,
    'be_sharesetting_name': EXPECTED_BE_SHARESETTING_NAME,
    'host_ip': EXPECTED_HOST_IP,
    'mount_path': EXPECTED_MOUNT_PATH,
}
