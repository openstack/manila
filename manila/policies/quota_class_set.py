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


BASE_POLICY_NAME = 'quota_class_set:%s'

DEPRECATED_REASON = """
The quota class API now supports scope and default roles.
"""

deprecated_quota_class_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_quota_class_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


quota_class_set_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Update quota class.",
        operations=[
            {
                'method': 'PUT',
                'path': '/quota-class-sets/{class_name}'
            },
            {
                'method': 'PUT',
                'path': '/os-quota-class-sets/{class_name}'
            }
        ],
        deprecated_rule=deprecated_quota_class_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get quota class.",
        operations=[
            {
                'method': 'GET',
                'path': '/quota-class-sets/{class_name}'
            },
            {
                'method': 'GET',
                'path': '/os-quota-class-sets/{class_name}'
            }
        ],
        deprecated_rule=deprecated_quota_class_show
    ),
]


def list_rules():
    return quota_class_set_policies
