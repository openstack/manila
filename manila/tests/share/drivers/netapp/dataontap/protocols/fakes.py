# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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

from manila.common import constants


SHARE_NAME = 'fake_share'
SHARE_ID = '9dba208c-9aa7-11e4-89d3-123b93f75cba'
EXPORT_POLICY_NAME = 'policy_9dba208c_9aa7_11e4_89d3_123b93f75cba'
SHARE_ADDRESS_1 = '10.10.10.10'
SHARE_ADDRESS_2 = '10.10.10.20'
CLIENT_ADDRESS_1 = '20.20.20.10'
CLIENT_ADDRESS_2 = '20.20.20.20'

CIFS_SHARE = {
    'export_location': r'\\%s\%s' % (SHARE_ADDRESS_1, SHARE_NAME),
    'id': SHARE_ID
}

NFS_SHARE_PATH = '/%s' % SHARE_NAME
NFS_SHARE = {
    'export_location': '%s:%s' % (SHARE_ADDRESS_1, NFS_SHARE_PATH),
    'id': SHARE_ID
}

IP_ACCESS = {
    'access_type': 'ip',
    'access_to': CLIENT_ADDRESS_1,
    'access_level': constants.ACCESS_LEVEL_RW,
}

USER_ACCESS = {
    'access_type': 'user',
    'access_to': 'fake_user',
    'access_level': constants.ACCESS_LEVEL_RW,
}

VOLUME = {
    'name': SHARE_NAME,
}

NEW_NFS_RULES = {
    '10.10.10.0/30': constants.ACCESS_LEVEL_RW,
    '10.10.10.0/24': constants.ACCESS_LEVEL_RO,
    '10.10.10.10': constants.ACCESS_LEVEL_RW,
    '10.10.20.0/24': constants.ACCESS_LEVEL_RW,
    '10.10.20.10': constants.ACCESS_LEVEL_RW,
}

EXISTING_CIFS_RULES = {
    'user1': constants.ACCESS_LEVEL_RW,
    'user2': constants.ACCESS_LEVEL_RO,
    'user3': constants.ACCESS_LEVEL_RW,
    'user4': constants.ACCESS_LEVEL_RO,
}

NEW_CIFS_RULES = {
    'user1': constants.ACCESS_LEVEL_RW,
    'user2': constants.ACCESS_LEVEL_RW,
    'user3': constants.ACCESS_LEVEL_RO,
    'user5': constants.ACCESS_LEVEL_RW,
    'user6': constants.ACCESS_LEVEL_RO,
}
