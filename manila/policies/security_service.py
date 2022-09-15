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


BASE_POLICY_NAME = 'security_service:%s'

DEPRECATED_REASON = """
The security service API now supports scope and default roles.
"""

deprecated_security_service_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_security_service_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_security_service_detail = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'detail',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_security_service_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_security_service_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_security_service_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_security_service_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all_security_services',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


security_service_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Create security service.",
        operations=[
            {
                'method': 'POST',
                'path': '/security-services'
            }
        ],
        deprecated_rule=deprecated_security_service_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get details of a security service.",
        operations=[
            {
                'method': 'GET',
                'path': '/security-services/{security_service_id}'
            }
        ],
        deprecated_rule=deprecated_security_service_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'detail',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get details of all security services.",
        operations=[
            {
                'method': 'GET',
                'path': '/security-services/detail?{query}'
            },
        ],
        deprecated_rule=deprecated_security_service_detail
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all security services under a project.",
        operations=[
            {
                'method': 'GET',
                'path': '/security-services?{query}'
            }
        ],
        deprecated_rule=deprecated_security_service_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update a security service.",
        operations=[
            {
                'method': 'PUT',
                'path': '/security-services/{security_service_id}',
            }
        ],
        deprecated_rule=deprecated_security_service_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete a security service.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/security-services/{security_service_id}'
            }
        ],
        deprecated_rule=deprecated_security_service_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all_security_services',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get security services of all projects.",
        operations=[
            {
                'method': 'GET',
                'path': '/security-services?all_tenants=1'
            },
            {
                'method': 'GET',
                'path': '/security-services/detail?all_tenants=1'
            }
        ],
        deprecated_rule=deprecated_security_service_get_all
    ),
]


def list_rules():
    return security_service_policies
