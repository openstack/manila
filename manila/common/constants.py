# Copyright 2013 OpenStack Foundation
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

STATUS_NEW = 'new'
STATUS_CREATING = 'creating'
STATUS_DELETING = 'deleting'
STATUS_DELETED = 'deleted'
STATUS_ERROR = 'error'
STATUS_ERROR_DELETING = 'error_deleting'
STATUS_AVAILABLE = 'available'
STATUS_ACTIVE = 'active'
STATUS_INACTIVE = 'inactive'
STATUS_OUT_OF_SYNC = 'out_of_sync'
STATUS_UPDATING = 'updating'
STATUS_UPDATING_MULTIPLE = 'updating_multiple'
STATUS_MANAGING = 'manage_starting'
STATUS_MANAGE_ERROR = 'manage_error'
STATUS_UNMANAGING = 'unmanage_starting'
STATUS_UNMANAGE_ERROR = 'unmanage_error'
STATUS_UNMANAGED = 'unmanaged'
STATUS_EXTENDING = 'extending'
STATUS_EXTENDING_ERROR = 'extending_error'
STATUS_SHRINKING = 'shrinking'
STATUS_SHRINKING_ERROR = 'shrinking_error'
STATUS_MIGRATING = 'migrating'
STATUS_MIGRATING_TO = 'migrating_to'
STATUS_SHRINKING_POSSIBLE_DATA_LOSS_ERROR = (
    'shrinking_possible_data_loss_error'
)
STATUS_REPLICATION_CHANGE = 'replication_change'

TASK_STATE_MIGRATION_STARTING = 'migration_starting'
TASK_STATE_MIGRATION_IN_PROGRESS = 'migration_in_progress'
TASK_STATE_MIGRATION_COMPLETING = 'migration_completing'
TASK_STATE_MIGRATION_SUCCESS = 'migration_success'
TASK_STATE_MIGRATION_ERROR = 'migration_error'
TASK_STATE_MIGRATION_CANCELLED = 'migration_cancelled'
TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS = 'migration_driver_in_progress'
TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE = 'migration_driver_phase1_done'
TASK_STATE_DATA_COPYING_STARTING = 'data_copying_starting'
TASK_STATE_DATA_COPYING_IN_PROGRESS = 'data_copying_in_progress'
TASK_STATE_DATA_COPYING_COMPLETING = 'data_copying_completing'
TASK_STATE_DATA_COPYING_COMPLETED = 'data_copying_completed'
TASK_STATE_DATA_COPYING_CANCELLED = 'data_copying_cancelled'
TASK_STATE_DATA_COPYING_ERROR = 'data_copying_error'

BUSY_TASK_STATES = (
    TASK_STATE_MIGRATION_STARTING,
    TASK_STATE_MIGRATION_IN_PROGRESS,
    TASK_STATE_MIGRATION_COMPLETING,
    TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
    TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
    TASK_STATE_DATA_COPYING_STARTING,
    TASK_STATE_DATA_COPYING_IN_PROGRESS,
    TASK_STATE_DATA_COPYING_COMPLETING,
    TASK_STATE_DATA_COPYING_COMPLETED,
)

BUSY_COPYING_STATES = (
    TASK_STATE_DATA_COPYING_STARTING,
    TASK_STATE_DATA_COPYING_IN_PROGRESS,
    TASK_STATE_DATA_COPYING_COMPLETING,
)

TRANSITIONAL_STATUSES = (
    STATUS_CREATING, STATUS_DELETING,
    STATUS_MANAGING, STATUS_UNMANAGING,
    STATUS_EXTENDING, STATUS_SHRINKING,
    STATUS_MIGRATING, STATUS_MIGRATING_TO,
)

UPDATING_RULES_STATUSES = (
    STATUS_UPDATING,
    STATUS_UPDATING_MULTIPLE,
)

SUPPORTED_SHARE_PROTOCOLS = (
    'NFS', 'CIFS', 'GLUSTERFS', 'HDFS', 'CEPHFS')

SECURITY_SERVICES_ALLOWED_TYPES = ['active_directory', 'ldap', 'kerberos']

NFS_EXPORTS_FILE = '/etc/exports'
NFS_EXPORTS_FILE_TEMP = '/var/lib/nfs/etab'

MOUNT_FILE = '/etc/fstab'
MOUNT_FILE_TEMP = '/etc/mtab'

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
WINRM_PORTS = (
    ("tcp", (5985, 5986)),
)

SERVICE_INSTANCE_SECGROUP_DATA = (
    CIFS_PORTS + NFS_PORTS + SSH_PORTS + PING_PORTS + WINRM_PORTS)

ACCESS_LEVEL_RW = 'rw'
ACCESS_LEVEL_RO = 'ro'

ACCESS_LEVELS = (
    ACCESS_LEVEL_RW,
    ACCESS_LEVEL_RO,
)

TASK_STATE_STATUSES = (
    TASK_STATE_MIGRATION_STARTING,
    TASK_STATE_MIGRATION_IN_PROGRESS,
    TASK_STATE_MIGRATION_COMPLETING,
    TASK_STATE_MIGRATION_SUCCESS,
    TASK_STATE_MIGRATION_ERROR,
    TASK_STATE_MIGRATION_CANCELLED,
    TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS,
    TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE,
    TASK_STATE_DATA_COPYING_STARTING,
    TASK_STATE_DATA_COPYING_IN_PROGRESS,
    TASK_STATE_DATA_COPYING_COMPLETING,
    TASK_STATE_DATA_COPYING_COMPLETED,
    TASK_STATE_DATA_COPYING_CANCELLED,
    TASK_STATE_DATA_COPYING_ERROR
)

REPLICA_STATE_ACTIVE = 'active'
REPLICA_STATE_IN_SYNC = 'in_sync'
REPLICA_STATE_OUT_OF_SYNC = 'out_of_sync'


class ExtraSpecs(object):

    # Extra specs key names
    DRIVER_HANDLES_SHARE_SERVERS = "driver_handles_share_servers"
    SNAPSHOT_SUPPORT = "snapshot_support"
    REPLICATION_TYPE_SPEC = "replication_type"

    # Extra specs containers
    REQUIRED = (
        DRIVER_HANDLES_SHARE_SERVERS,
    )
    UNDELETABLE = (
        DRIVER_HANDLES_SHARE_SERVERS,
        SNAPSHOT_SUPPORT,
    )
    # NOTE(cknight): Some extra specs are necessary parts of the Manila API and
    # should be visible to non-admin users. UNDELETABLE specs are user-visible.
    TENANT_VISIBLE = UNDELETABLE + (REPLICATION_TYPE_SPEC, )
    BOOLEAN = (
        DRIVER_HANDLES_SHARE_SERVERS,
        SNAPSHOT_SUPPORT,
    )
