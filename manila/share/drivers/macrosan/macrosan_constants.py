# Copyright (c) 2022 MacroSAN Technologies Co., Ltd.
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

NFS_NON_CONFIG = 0
NFS_ENABLED = 1
NFS_DISABLED = 2
NFS_EXCEPTION = 3
NFS_NON_SUPPORTED = 0
NFS_SUPPORTED = 1

CIFS_SHARE_MODE = '2'
CIFS_ENABLED = '1'
CIFS_NON_CONFIG = '-1'
CIFS_DISABLED = '-2'
CIFS_EXCEPTION = '-3'

USER_NOT_EXIST = '0'
USER_EXIST = '1'
USER_FORMAT_ERROR = '2'

GROUP_NOT_EXIST = '0'
GROUP_EXIST = '1'
GROUP_FORMAT_ERROR = '2'

CODE_SUCCESS = 0
CODE_NOT_FOUND = 4
CODE_SOURCE_NOT_EXIST = 403

TOKEN_EXPIRED = 301
TOKEN_VERIFY_FAILED = 302
TOKEN_FORMAT_ERROR = 303
TOKEN_REQUIRED = 304
