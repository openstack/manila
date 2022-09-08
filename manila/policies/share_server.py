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

from manila.policies import base


BASE_POLICY_NAME = 'share_server:%s'

DEPRECATED_REASON = """
The share server API now supports scope and default roles.
"""

deprecated_server_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_details = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'details',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_manage_server = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'manage_share_server',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_unmanage_server = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'unmanage_share_server',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_reset_status = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_status',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_migration_start = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'share_server_migration_start',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_migration_check = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'share_server_migration_check',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_migration_complete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'share_server_migration_complete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_migration_cancel = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'share_server_migration_cancel',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_migration_get_progress = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'share_server_migration_get_progress',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_server_reset_task_state = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'share_server_reset_task_state',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


share_server_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get share servers.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-servers?{query}',
            }
        ],
        deprecated_rule=deprecated_server_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Show share server.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-servers/{server_id}',
            }
        ],
        deprecated_rule=deprecated_server_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'details',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get share server details.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-servers/{server_id}/details',
            }
        ],
        deprecated_rule=deprecated_server_details
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Delete share server.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-servers/{server_id}',
            }
        ],
        deprecated_rule=deprecated_server_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'manage_share_server',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Manage share server.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/manage'
            }
        ],
        deprecated_rule=deprecated_manage_server
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'unmanage_share_server',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Unmanage share server.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action'
            }
        ],
        deprecated_rule=deprecated_unmanage_server
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset the status of a share server.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action'
            }
        ],
        deprecated_rule=deprecated_server_reset_status
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_start',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Migrates a share server to the specified host.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ],
        deprecated_rule=deprecated_server_migration_start
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_check',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Check if can migrates a share server to the specified "
                    "host.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ],
        deprecated_rule=deprecated_server_migration_check
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_complete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Invokes the 2nd phase of share server migration.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ],
        deprecated_rule=deprecated_server_migration_complete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_cancel',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Attempts to cancel share server migration.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ],
        deprecated_rule=deprecated_server_migration_cancel
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_get_progress',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=("Retrieves the share server migration progress for a "
                     "given share server."),
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ],
        deprecated_rule=deprecated_server_migration_get_progress
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_reset_task_state',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Resets task state.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ],
        deprecated_rule=deprecated_server_reset_task_state
    ),
]


def list_rules():
    return share_server_policies
