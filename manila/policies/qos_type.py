# Copyright 2026 SAP SE.
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

from oslo_policy import policy

from manila.policies import base


BASE_POLICY_NAME = 'qos_type:%s'

DEPRECATED_REASON = """
The qos type API now supports scope and default roles.
"""

deprecated_qos_type_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)
deprecated_qos_type_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)
deprecated_qos_type_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)
deprecated_qos_type_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)
deprecated_qos_type_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)


qos_type_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Create qos type.',
        operations=[
            {
                'method': 'POST',
                'path': '/qos-types',
            }
        ],
        deprecated_rule=deprecated_qos_type_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Update qos type.',
        operations=[
            {
                'method': 'PUT',
                'path': '/qos-types/{qos_type_id}',
            }
        ],
        deprecated_rule=deprecated_qos_type_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='Get qos type.',
        operations=[
            {
                'method': 'GET',
                'path': '/qos-types/{qos_type_id}',
            }
        ],
        deprecated_rule=deprecated_qos_type_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='List qos types.',
        operations=[
            {
                'method': 'GET',
                'path': '/qos-types',
            },
            {
                'method': 'GET',
                'path': '/qos-types?{query}'
            },
        ],
        deprecated_rule=deprecated_qos_type_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Delete qos type.',
        operations=[
            {
                'method': 'DELETE',
                'path': '/qos-types/{qos_type_id}',
            }
        ],
        deprecated_rule=deprecated_qos_type_delete
    ),
]


def list_rules():
    return qos_type_policies
