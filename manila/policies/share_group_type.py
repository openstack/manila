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


BASE_POLICY_NAME = 'share_group_type:%s'

DEPRECATED_REASON = """
The share group type API now supports scope and default roles.
"""

deprecated_share_group_type_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_group_type_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_group_type_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_group_type_get_default = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'default',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_group_type_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_group_type_project_access = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'list_project_access',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_group_type_add_project = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'add_project_access',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_group_type_remove_project = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'remove_project_access',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


share_group_type_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Create a new share group type.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-types',
            }
        ],
        deprecated_rule=deprecated_share_group_type_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get the list of share group types.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-types?is_public=all',
            }
        ],
        deprecated_rule=deprecated_share_group_type_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get details regarding the specified share group type.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-types/{share_group_type_id}',
            }
        ],
        deprecated_rule=deprecated_share_group_type_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'default',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get the default share group type.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-types/default',
            }
        ],
        deprecated_rule=deprecated_share_group_type_get_default
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Delete an existing group type.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-group-types/{share_group_type_id}'
            }
        ],
        deprecated_rule=deprecated_share_group_type_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'list_project_access',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get project access by share group type.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-types/{share_group_type_id}/access',
            }
        ],
        deprecated_rule=deprecated_share_group_type_project_access
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'add_project_access',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Allow project to use the share group type.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-types/{share_group_type_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_group_type_add_project
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'remove_project_access',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Deny project access to use the share group type.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-types/{share_group_type_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_group_type_remove_project
    ),
]


def list_rules():
    return share_group_type_policies
