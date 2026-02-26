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


BASE_POLICY_NAME = 'qos_type_specs:%s'

DEPRECATED_REASON = """
The qos types specs API now supports scope and default roles.
"""

deprecated_spec_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)
deprecated_spec_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)
deprecated_spec_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)
deprecated_spec_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)
deprecated_spec_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2026.1/Gazpacho'
)


qos_types_spec_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Create qos type spec.",
        operations=[
            {
                'method': 'POST',
                'path': '/qos-types/{qos_type_id}/specs',
            }
        ],
        deprecated_rule=deprecated_spec_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get qos type specs of a given qos type.",
        operations=[
            {
                'method': 'GET',
                'path': '/qos-types/{qos_type_id}/specs',
            }
        ],
        deprecated_rule=deprecated_spec_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get details of a qos type spec.",
        operations=[
            {
                'method': 'GET',
                'path': '/qos-types/{qos_type_id}/specs/{key}',
            },
        ],
        deprecated_rule=deprecated_spec_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Update qos type spec.",
        operations=[
            {
                'method': 'PUT',
                'path': '/qos-types/{qos_type_id}/specs/{key}',
            }
        ],
        deprecated_rule=deprecated_spec_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Delete qos type spec.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/qos-types/{qos_type_id}/specs/{key}',
            }
        ],
        deprecated_rule=deprecated_spec_delete
    ),
]


def list_rules():
    return qos_types_spec_policies
