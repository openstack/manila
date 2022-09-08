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


BASE_POLICY_NAME = 'quota_set:%s'

DEPRECATED_REASON = """
The quota API now supports scope and default roles.
"""

deprecated_quota_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_quota_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_quota_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


quota_set_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=("Update the quotas for a project/user and/or share "
                     "type."),
        operations=[
            {
                'method': 'PUT',
                'path': '/quota-sets/{project_id}'
            },
            {
                'method': 'PUT',
                'path': '/quota-sets/{project_id}?user_id={user_id}'
            },
            {
                'method': 'PUT',
                'path': '/quota-sets/{project_id}?share_type={share_type_id}'
            },
            {
                'method': 'PUT',
                'path': '/os-quota-sets/{project_id}'
            },
            {
                'method': 'PUT',
                'path': '/os-quota-sets/{project_id}?user_id={user_id}'
            },
        ],
        deprecated_rule=deprecated_quota_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="List the quotas for a project/user.",
        operations=[
            {
                'method': 'GET',
                'path': '/quota-sets/{project_id}/defaults'
            },
            {
                'method': 'GET',
                'path': '/os-quota-sets/{project_id}/defaults'
            }
        ],
        deprecated_rule=deprecated_quota_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=("Delete quota for a project/user or "
                     "project/share-type. The quota will revert back to "
                     "default (Admin only)."),
        operations=[
            {
                'method': 'DELETE',
                'path': '/quota-sets/{project_id}'
            },
            {
                'method': 'DELETE',
                'path': '/quota-sets/{project_id}?user_id={user_id}'
            },
            {
                'method': 'DELETE',
                'path': '/quota-sets/{project_id}?share_type={share_type_id}'
            },
            {
                'method': 'DELETE',
                'path': '/os-quota-sets/{project_id}'
            },
            {
                'method': 'DELETE',
                'path': '/os-quota-sets/{project_id}?user_id={user_id}'
            },
        ],
        deprecated_rule=deprecated_quota_delete
    ),
]


def list_rules():
    return quota_set_policies
