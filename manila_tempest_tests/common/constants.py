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

# Shares
STATUS_ERROR = 'error'
STATUS_AVAILABLE = 'available'
STATUS_ERROR_DELETING = 'error_deleting'
STATUS_MIGRATING = 'migrating'

TEMPEST_MANILA_PREFIX = 'tempest-manila'

# Replication
REPLICATION_STYLE_READABLE = 'readable'
REPLICATION_STYLE_WRITABLE = 'writable'
REPLICATION_STYLE_DR = 'dr'
REPLICATION_TYPE_CHOICES = (
    REPLICATION_STYLE_READABLE,
    REPLICATION_STYLE_WRITABLE,
    REPLICATION_STYLE_DR,
)
REPLICATION_PROMOTION_CHOICES = (
    REPLICATION_STYLE_READABLE,
    REPLICATION_STYLE_DR,
)
REPLICATION_STATE_ACTIVE = 'active'
REPLICATION_STATE_IN_SYNC = 'in_sync'
REPLICATION_STATE_OUT_OF_SYNC = 'out_of_sync'

# Access Rules
RULE_STATE_ACTIVE = 'active'
RULE_STATE_OUT_OF_SYNC = 'out_of_sync'
RULE_STATE_ERROR = 'error'

TASK_STATE_MIGRATION_STARTING = 'migration_starting'
TASK_STATE_MIGRATION_IN_PROGRESS = 'migration_in_progress'
TASK_STATE_MIGRATION_COMPLETING = 'migration_completing'
TASK_STATE_MIGRATION_SUCCESS = 'migration_success'
TASK_STATE_MIGRATION_ERROR = 'migration_error'
TASK_STATE_MIGRATION_CANCELLED = 'migration_cancelled'
TASK_STATE_MIGRATION_DRIVER_STARTING = 'migration_driver_starting'
TASK_STATE_MIGRATION_DRIVER_IN_PROGRESS = 'migration_driver_in_progress'
TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE = 'migration_driver_phase1_done'
TASK_STATE_DATA_COPYING_STARTING = 'data_copying_starting'
TASK_STATE_DATA_COPYING_IN_PROGRESS = 'data_copying_in_progress'
TASK_STATE_DATA_COPYING_COMPLETING = 'data_copying_completing'
TASK_STATE_DATA_COPYING_COMPLETED = 'data_copying_completed'
TASK_STATE_DATA_COPYING_CANCELLED = 'data_copying_cancelled'
TASK_STATE_DATA_COPYING_ERROR = 'data_copying_error'

# Revert to snapshot
REVERT_TO_SNAPSHOT_MICROVERSION = '2.27'
REVERT_TO_SNAPSHOT_SUPPORT = 'revert_to_snapshot_support'
STATUS_RESTORING = 'restoring'
STATUS_REVERTING = 'reverting'
STATUS_REVERTING_ERROR = 'reverting_error'

# Share groups
MIN_SHARE_GROUP_MICROVERSION = '2.31'
SHARE_GROUP_SIMPLE_KEYS = {
    'id', 'name', 'links',
}
SHARE_GROUP_DETAIL_REQUIRED_KEYS = {
    'id', 'name', 'description', 'created_at', 'status', 'share_types',
    'project_id', 'host', 'links', 'share_group_type_id',
}
SHARE_GROUP_SNAPSHOT_SIMPLE_KEYS = {
    'id', 'name', 'links',
}
SHARE_GROUP_SNAPSHOT_DETAIL_REQUIRED_KEYS = {
    'id', 'name', 'description', 'created_at', 'status', 'project_id',
    'links', 'share_group_id', 'members',
}

SHARE_GROUP_TYPE_REQUIRED_KEYS = {
    'id', 'name', 'share_types', 'is_public', 'group_specs',
}
