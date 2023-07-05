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


BASE_POLICY_NAME = 'resource_lock:%s'

DEPRECATED_REASON = """
The resource lock API now supports scope and default roles.
"""

deprecated_lock_get = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_lock_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_lock_get_all_projects = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all_projects',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_lock_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat'
)
deprecated_lock_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_ADMIN_OR_OWNER_USER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_lock_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_ADMIN_OR_OWNER_USER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)
deprecated_bypass_locked_show_action = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'bypass_locked_show_action',
    check_str=base.RULE_ADMIN_OR_OWNER_USER,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2023.2/Bobcat',
)

# We anticipate bypassing is desirable only for resource visibility locks.
# Without a bypass, the lock would have to be set aside each time the lock
# owner wants to view the resource.

lock_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.ADMIN_OR_SERVICE_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get details of a given resource lock.",
        operations=[
            {
                'method': 'GET',
                'path': '/resource-locks/{lock_id}'
            }
        ],
        deprecated_rule=deprecated_lock_get,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.ADMIN_OR_SERVICE_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all resource locks.",
        operations=[
            {
                'method': 'GET',
                'path': '/resource-locks'
            },
            {
                'method': 'GET',
                'path': '/resource-locks?{query}'
            }
        ],
        deprecated_rule=deprecated_lock_get_all,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all_projects',
        check_str=base.ADMIN_OR_SERVICE,
        scope_types=['project'],
        description="Get resource locks from all project namespaces.",
        operations=[
            {
                'method': 'GET',
                'path': '/resource-locks?all_projects=1'
            },
            {
                'method': 'GET',
                'path': '/resource-locks?all_projects=1&'
                        'project_id={project_id}'
            }
        ],
        deprecated_rule=deprecated_lock_get_all_projects,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN_OR_SERVICE_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Create a resource lock.",
        operations=[
            {
                'method': 'POST',
                'path': '/resource-locks'
            }
        ],
        deprecated_rule=deprecated_lock_create,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN_OR_SERVICE_OR_OWNER_USER,
        scope_types=['project'],
        description="Update a resource lock.",
        operations=[
            {
                'method': 'PUT',
                'path': '/resource-locks/{lock_id}'
            }
        ],
        deprecated_rule=deprecated_lock_update,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN_OR_SERVICE_OR_OWNER_USER,
        scope_types=['project'],
        description="Delete a resource lock.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/resource-locks/{lock_id}'
            }
        ],
        deprecated_rule=deprecated_lock_delete,
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'bypass_locked_show_action',
        check_str=base.ADMIN_OR_SERVICE_OR_OWNER_USER,
        scope_types=['project'],
        description="Bypass a visibility lock placed in a resource.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-access-rules/{share_access_id}'
            },
            {
                'method': 'GET',
                'path': ('/share-access-rules?share_id={share_id}'
                         '&key1=value1&key2=value2')
            },
        ],
        deprecated_rule=deprecated_bypass_locked_show_action,
    ),
]


def list_rules():
    return lock_policies
