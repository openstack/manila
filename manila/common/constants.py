# Copyright 2013 Openstack Foundation
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

STATUS_NEW = 'NEW'
STATUS_CREATING = 'CREATING'
STATUS_DELETING = 'DELETING'
STATUS_DELETED = 'DELETED'
STATUS_ERROR = 'ERROR'
STATUS_ACTIVE = 'ACTIVE'
STATUS_INACTIVE = 'INACTIVE'
STATUS_ACTIVATING = 'ACTIVATING'
STATUS_DEACTIVATING = 'DEACTIVATING'

SECURITY_SERVICES_ALLOWED_TYPES = ['active_directory', 'ldap', 'kerberos']

# Below represented ports are ranges (from, to)
CIFS_PORTS = (
    ("tcp", (445, 445)),
    ("tcp", (137, 139)),
    ("udp", (137, 139)),
    ("udp", (445, 445)),
)
NFS_PORTS = (
    ("tcp", (2049, 2049)),
    ("udp", (2049, 2049)),
)
SSH_PORTS = (
    ("tcp", (22, 22)),
)
PING_PORTS = (
    ("icmp", (-1, -1)),
)

SERVICE_INSTANCE_SECGROUP_DATA = (
    CIFS_PORTS + NFS_PORTS + SSH_PORTS + PING_PORTS)
