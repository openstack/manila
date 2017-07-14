# Copyright (c) 2016 Dell Inc. or its subsidiaries.
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

STATUS_OK = 'ok'
STATUS_INFO = 'info'
STATUS_DEBUG = 'debug'
STATUS_WARNING = 'warning'
STATUS_ERROR = 'error'
STATUS_NOT_FOUND = 'not_found'

MSG_GENERAL_ERROR = '13690601492'
MSG_INVALID_VDM_ID = '14227341325'
MSG_INVALID_MOVER_ID = '14227341323'

MSG_FILESYSTEM_NOT_FOUND = "18522112101"
MSG_FILESYSTEM_EXIST = '13691191325'

MSG_VDM_EXIST = '13421840550'

MSG_SNAP_EXIST = '13690535947'

MSG_INTERFACE_NAME_EXIST = '13421840550'
MSG_INTERFACE_EXIST = '13691781136'
MSG_INTERFACE_INVALID_VLAN_ID = '13421850371'
MSG_INTERFACE_NON_EXISTENT = '13691781134'

MSG_JOIN_DOMAIN = '13157007726'
MSG_UNJOIN_DOMAIN = '13157007723'

# Necessary to retry when ENAS database is locked for provisioning operation
MSG_CODE_RETRY = '13421840537'

IP_ALLOCATIONS = 2

CONTENT_TYPE_URLENCODE = {'Content-Type': 'application/x-www-form-urlencoded'}

XML_HEADER = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
XML_NAMESPACE = 'http://www.emc.com/schemas/celerra/xml_api'

CIFS_ACL_FULLCONTROL = 'fullcontrol'
CIFS_ACL_READ = 'read'

SSH_DEFAULT_RETRY_PATTERN = r'Error 2201:.*: unable to acquire lock\(s\)'
