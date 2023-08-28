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

from oslo_policy import policy

from manila.policies import base


BASE_POLICY_NAME = 'share_backup:%s'

DEPRECATED_REASON = """
The share backup API now supports system scope and default roles.
"""

deprecated_backup_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat'
)
deprecated_backup_get = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_backup_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_get_all_project = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all_project',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_backup_restore = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'restore',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_backup_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_backup_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_ADMIN_OR_OWNER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_backup_reset_status = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_status',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)


share_backup_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Create share backup.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-backups'
            }
        ],
        deprecated_rule=deprecated_backup_create,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get share backup.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-backups/{backup_id}'
            }
        ],
        deprecated_rule=deprecated_backup_get,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all share backups.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-backups'
            },
            {
                'method': 'GET',
                'path': '/share-backups/detail'
            },
            {
                'method': 'GET',
                'path': '/share-backups/detail?share_id=(share_id}',
            },
        ],
        deprecated_rule=deprecated_backup_get_all,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all_project',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get share backups of all projects.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-backups?all_tenants=1'
            },
            {
                'method': 'GET',
                'path': '/share-backups/detail?all_tenants=1'
            }
        ],
        deprecated_rule=deprecated_get_all_project
    ),

    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'restore',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Restore a share backup.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-backups/{backup_id}/action'
            }
        ],
        deprecated_rule=deprecated_backup_restore,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset status.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-backups/{backup_id}/action',
            }
        ],
        deprecated_rule=deprecated_backup_reset_status
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update a share backup.",
        operations=[
            {
                'method': 'PUT',
                'path': '/share-backups/{backup_id}',
            }
        ],
        deprecated_rule=deprecated_backup_update,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Force Delete a share backup.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-backups/{backup_id}'
            }
        ],
        deprecated_rule=deprecated_backup_delete,
    ),

]


def list_rules():
    return share_backup_policies
