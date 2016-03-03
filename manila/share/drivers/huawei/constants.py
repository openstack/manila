# Copyright (c) 2014 Huawei Technologies Co., Ltd.
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

STATUS_ETH_RUNNING = "10"
STATUS_FS_HEALTH = "1"
STATUS_FS_RUNNING = "27"
STATUS_JOIN_DOMAIN = '1'
STATUS_EXIT_DOMAIN = '0'
STATUS_SERVICE_RUNNING = "2"
STATUS_QOS_ACTIVE = '2'

DEFAULT_WAIT_INTERVAL = 3
DEFAULT_TIMEOUT = 60

MAX_FS_NUM_IN_QOS = 64
MSG_SNAPSHOT_NOT_FOUND = 1073754118
IP_ALLOCATIONS_DHSS_FALSE = 0
IP_ALLOCATIONS_DHSS_TRUE = 1
SOCKET_TIMEOUT = 52
LOGIN_SOCKET_TIMEOUT = 4
QOS_NAME_PREFIX = 'OpenStack_'
SYSTEM_NAME_PREFIX = "Array-"
MIN_ARRAY_VERSION_FOR_QOS = 'V300R003C00'
TMP_PATH_SRC_PREFIX = "huawei_manila_tmp_path_src_"
TMP_PATH_DST_PREFIX = "huawei_manila_tmp_path_dst_"

ACCESS_NFS_RW = "1"
ACCESS_NFS_RO = "0"
ACCESS_CIFS_FULLCONTROL = "1"
ACCESS_CIFS_RO = "0"

ERROR_CONNECT_TO_SERVER = -403
ERROR_UNAUTHORIZED_TO_SERVER = -401
ERROR_LOGICAL_PORT_EXIST = 1073813505
ERROR_USER_OR_GROUP_NOT_EXIST = 1077939723

PORT_TYPE_ETH = '1'
PORT_TYPE_BOND = '7'
PORT_TYPE_VLAN = '8'

SORT_BY_VLAN = 1
SORT_BY_LOGICAL = 2

ALLOC_TYPE_THIN_FLAG = "1"
ALLOC_TYPE_THICK_FLAG = "0"

ALLOC_TYPE_THIN = "Thin"
ALLOC_TYPE_THICK = "Thick"
THIN_PROVISIONING = "true"
THICK_PROVISIONING = "false"

OPTS_QOS_VALUE = {
    'maxiops': None,
    'miniops': None,
    'minbandwidth': None,
    'maxbandwidth': None,
    'latency': None,
    'iotype': None
}

QOS_LOWER_LIMIT = ['MINIOPS', 'LATENCY', 'MINBANDWIDTH']
QOS_UPPER_LIMIT = ['MAXIOPS', 'MAXBANDWIDTH']

OPTS_CAPABILITIES = {
    'dedupe': False,
    'compression': False,
    'huawei_smartcache': False,
    'huawei_smartpartition': False,
    'thin_provisioning': None,
    'qos': False,
}

OPTS_VALUE = {
    'cachename': None,
    'partitionname': None,
}

OPTS_VALUE.update(OPTS_QOS_VALUE)

OPTS_ASSOCIATE = {
    'huawei_smartcache': 'cachename',
    'huawei_smartpartition': 'partitionname',
    'qos': OPTS_QOS_VALUE,
}
