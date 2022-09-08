# Copyright (c) 2017 Huawei Technologies Co., Ltd.
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

from oslo_log import versionutils
from oslo_policy import policy

from manila.policies import base


BASE_POLICY_NAME = 'share_type:%s'

DEPRECATED_REASON = """
The share type API now supports scope and default roles.
"""

deprecated_share_type_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_type_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_type_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_type_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_type_get_default = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'default',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_type_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_type_list_project_access = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'list_project_access',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_type_add_project_access = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'add_project_access',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_type_remove_project_access = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'remove_project_access',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


share_type_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create share type.',
        operations=[
            {
                'method': 'POST',
                'path': '/types',
            }
        ],
        deprecated_rule=deprecated_share_type_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update share type.',
        operations=[
            {
                'method': 'PUT',
                'path': '/types/{share_type_id}',
            }
        ],
        deprecated_rule=deprecated_share_type_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='Get share type.',
        operations=[
            {
                'method': 'GET',
                'path': '/types/{share_type_id}',
            }
        ],
        deprecated_rule=deprecated_share_type_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='List share types.',
        operations=[
            {
                'method': 'GET',
                'path': '/types?is_public=all',
            }
        ],
        deprecated_rule=deprecated_share_type_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'default',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='Get default share type.',
        operations=[
            {
                'method': 'GET',
                'path': '/types/default',
            }
        ],
        deprecated_rule=deprecated_share_type_get_default
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete share type.',
        operations=[
            {
                'method': 'DELETE',
                'path': '/types/{share_type_id}',
            }
        ],
        deprecated_rule=deprecated_share_type_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'list_project_access',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='List share type project access.',
        operations=[
            {
                'method': 'GET',
                'path': '/types/{share_type_id}',
            }
        ],
        deprecated_rule=deprecated_share_type_list_project_access
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'add_project_access',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Add share type to project.',
        operations=[
            {
                'method': 'POST',
                'path': '/types/{share_type_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_type_add_project_access
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'remove_project_access',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Remove share type from project.',
        operations=[
            {
                'method': 'POST',
                'path': '/types/{share_type_id}/action',
            }
        ],
        deprecated_rule=deprecated_share_type_remove_project_access
    ),
]


def list_rules():
    return share_type_policies
