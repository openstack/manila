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


BASE_POLICY_NAME = 'share_types_extra_spec:%s'

DEPRECATED_REASON = """
The share types extra specs API now supports scope and default roles.
"""

deprecated_extra_spec_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_extra_spec_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_extra_spec_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_extra_spec_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_extra_spec_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


share_types_extra_spec_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Create share type extra spec.",
        operations=[
            {
                'method': 'POST',
                'path': '/types/{share_type_id}/extra_specs',
            }
        ],
        deprecated_rule=deprecated_extra_spec_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get share type extra specs of a given share type.",
        operations=[
            {
                'method': 'GET',
                'path': '/types/{share_type_id}/extra_specs',
            }
        ],
        deprecated_rule=deprecated_extra_spec_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get details of a share type extra spec.",
        operations=[
            {
                'method': 'GET',
                'path': '/types/{share_type_id}/extra_specs/{extra_spec_id}',
            },
        ],
        deprecated_rule=deprecated_extra_spec_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Update share type extra spec.",
        operations=[
            {
                'method': 'PUT',
                'path': '/types/{share_type_id}/extra_specs',
            }
        ],
        deprecated_rule=deprecated_extra_spec_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Delete share type extra spec.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/types/{share_type_id}/extra_specs/{key}',
            }
        ],
        deprecated_rule=deprecated_extra_spec_delete
    ),
]


def list_rules():
    return share_types_extra_spec_policies
