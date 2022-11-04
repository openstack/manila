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

from oslo_log import versionutils
from oslo_policy import policy

from manila.common import constants
from manila.policies import base


BASE_POLICY_NAME = 'share:%s'

DEPRECATED_REASON = """
The share API now supports scope and default roles.
"""

# Deprecated share policies
deprecated_share_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str="",
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_create_public = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create_public_share',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_get = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_set_public = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'set_public_share',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_force_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'force_delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_manage = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'manage',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_unmanage = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'unmanage',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_list_by_host = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'list_by_host',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_list_by_server_id = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'list_by_share_server_id',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_access_get = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'access_get',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_access_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'access_get_all',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_extend = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'extend',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_shrink = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'shrink',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_migration_start = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'migration_start',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_migration_complete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'migration_complete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_migration_cancel = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'migration_cancel',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_migration_get_progress = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'migration_get_progress',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_reset_task_state = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_task_state',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_reset_status = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_status',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_revert_to_snapshot = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'revert_to_snapshot',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_allow_access = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'allow_access',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_deny_access = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'deny_access',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_update_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update_share_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_delete_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete_share_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_get_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_share_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)

# deprecated legacy snapshot policies with "share" as base resource
deprecated_share_create_snapshot = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create_snapshot',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_delete_snapshot = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete_snapshot',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_snapshot_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'snapshot_update',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)

deprecated_update_admin_only_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update_admin_only_metadata',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since="YOGA"
)

shares_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Create share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares',
            }
        ],
        deprecated_rule=deprecated_share_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create_public_share',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Create shares visible across all projects in the cloud.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares',
            }
        ],
        deprecated_rule=deprecated_share_create_public
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get share.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares/{share_id}',
            }
        ],
        deprecated_rule=deprecated_share_get
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="List shares.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares?{query}',
            },
            {
                'method': 'GET',
                'path': '/shares/detail?{query}',
            }
        ],
        deprecated_rule=deprecated_share_get_all
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update a share.",
        operations=[
            {
                'method': 'PUT',
                'path': '/shares/{share_id}',
            }
        ],
        deprecated_rule=deprecated_share_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'set_public_share',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Update a share to be visible across all projects in the "
                    "cloud.",
        operations=[
            {
                'method': 'PUT',
                'path': '/shares/{share_id}',
            }
        ],
        deprecated_rule=deprecated_share_set_public
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete share.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/shares/{share_id}',
            }
        ],
        deprecated_rule=deprecated_share_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'soft_delete',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Soft Delete a share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'restore',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Restore a share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Force Delete a share.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/shares/{share_id}',
            }
        ],
        deprecated_rule=deprecated_share_force_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'manage',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Manage share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/manage',
            }
        ],
        deprecated_rule=deprecated_share_manage
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'unmanage',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Unmanage share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/unmanage',
            }
        ],
        deprecated_rule=deprecated_share_unmanage
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'list_by_host',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="List share by host.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares?host={host}',
            },
            {
                'method': 'GET',
                'path': '/shares/detail?host={host}',
            }
        ],
        deprecated_rule=deprecated_share_list_by_host
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'list_by_share_server_id',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="List share by server id.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares?share_server_id={share_server_id}'
            },
            {
                'method': 'GET',
                'path': '/shares/detail?share_server_id={share_server_id}',
            }
        ],
        deprecated_rule=deprecated_share_list_by_server_id
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'access_get',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get share access rule (deprecated in API version 2.45).",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_access_get
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'access_get_all',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description=("List share access rules (deprecated in API "
                     "version 2.45)."),
        operations=[
            {
                'method': 'GET',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_access_get_all
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'extend',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Extend share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_extend
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_extend',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Force extend share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % constants.POLICY_EXTEND_BEYOND_MAX_SHARE_SIZE,
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Extend share beyond max share size.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'shrink',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Shrink share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_shrink
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'migration_start',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Migrate a share to the specified host.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_migration_start
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'migration_complete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Invoke 2nd phase of share migration.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_migration_complete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'migration_cancel',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Attempt to cancel share migration.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_migration_cancel
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'migration_get_progress',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=("Retrieve share migration progress for a given "
                     "share."),
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_migration_get_progress
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_task_state',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset task state.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_reset_task_state
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset status.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_reset_status
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'revert_to_snapshot',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Revert a share to a snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_revert_to_snapshot
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'allow_access',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Add share access rule.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_allow_access
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'deny_access',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Remove share access rule.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_deny_access
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update_share_metadata',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update share metadata.",
        operations=[
            {
                'method': 'PUT',
                'path': '/shares/{share_id}/metadata',
            },
            {
                'method': 'POST',
                'path': '/shares/{share_id}/metadata/{key}',
            },
            {
                'method': 'POST',
                'path': '/shares/{share_id}/metadata',
            },
        ],
        deprecated_rule=deprecated_share_update_metadata
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete_share_metadata',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete share metadata.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/shares/{share_id}/metadata/{key}',
            }
        ],
        deprecated_rule=deprecated_share_delete_metadata
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_share_metadata',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get share metadata.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares/{share_id}/metadata',
            },
            {
                'method': 'GET',
                'path': '/shares/{share_id}/metadata/{key}',
            }
        ],
        deprecated_rule=deprecated_share_get_metadata
    ),
]

# NOTE(gouthamr) For historic reasons, some snapshot policies used
# "share" as the resource. We could deprecate these and move them to using
# "share_snapshot" as the base resource in the future.
base_snapshot_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create_snapshot',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Create share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots',
            }
        ],
        deprecated_rule=deprecated_share_create_snapshot
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete_snapshot',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete share snapshot.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/snapshots/{snapshot_id}',
            }
        ],
        deprecated_rule=deprecated_share_delete_snapshot
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'snapshot_update',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update share snapshot.",
        operations=[
            {
                'method': 'PUT',
                'path': '/snapshots/{snapshot_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_snapshot_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update_admin_only_metadata',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=(
            "Update metadata items that are considered \"admin only\" "
            "by the service."),
        operations=[
            {
                'method': 'PUT',
                'path': '/shares/{share_id}/metadata',
            }
        ],
        deprecated_rule=deprecated_update_admin_only_metadata
    ),
]


def list_rules():
    return shares_policies + base_snapshot_policies
