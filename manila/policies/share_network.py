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

BASE_POLICY_NAME = 'share_network:%s'

DEPRECATED_REASON = """
The share network API now support system scope and default roles.
"""

deprecated_share_network_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_DEFAULT
)
deprecated_share_network_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT
)
deprecated_share_network_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_DEFAULT
)
deprecated_share_network_detail = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'detail',
    check_str=base.RULE_DEFAULT
)
deprecated_share_network_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_DEFAULT
)
deprecated_share_network_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_DEFAULT
)
deprecated_share_network_add_security_service = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'add_security_service',
    check_str=base.RULE_DEFAULT
)
deprecated_share_network_remove_security_service = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'remove_security_service',
    check_str=base.RULE_DEFAULT
)
deprecated_share_network_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all_share_networks',
    check_str=base.RULE_ADMIN_API
)


share_network_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['system', 'project'],
        description="Create share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks'
            }
        ],
        deprecated_rule=deprecated_share_network_create,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.SYSTEM_OR_PROJECT_READER,
        scope_types=['system', 'project'],
        description="Get details of a share network.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks/{share_network_id}'
            }
        ],
        deprecated_rule=deprecated_share_network_show,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.SYSTEM_OR_PROJECT_READER,
        scope_types=['system', 'project'],
        description="Get all share networks.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks'
            },
            {
                'method': 'GET',
                'path': '/share-networks?{query}'
            }
        ],
        deprecated_rule=deprecated_share_network_index,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'detail',
        check_str=base.SYSTEM_OR_PROJECT_READER,
        scope_types=['system', 'project'],
        description="Get details of share networks .",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks/detail?{query}'
            },
            {
                'method': 'GET',
                'path': '/share-networks/detail'
            },
        ],
        deprecated_rule=deprecated_share_network_detail,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['system', 'project'],
        description="Update a share network.",
        operations=[
            {
                'method': 'PUT',
                'path': '/share-networks/{share_network_id}'
            }
        ],
        deprecated_rule=deprecated_share_network_update,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['system', 'project'],
        description="Delete a share network.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-networks/{share_network_id}'
            }
        ],
        deprecated_rule=deprecated_share_network_delete,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'add_security_service',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['system', 'project'],
        description="Add security service to share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ],
        deprecated_rule=deprecated_share_network_add_security_service,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'remove_security_service',
        check_str=base.SYSTEM_ADMIN_OR_PROJECT_MEMBER,
        scope_types=['system', 'project'],
        description="Remove security service from share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ],
        deprecated_rule=deprecated_share_network_remove_security_service,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all_share_networks',
        check_str=base.SYSTEM_READER,
        scope_types=['system'],
        description="Get share networks belonging to all projects.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks?all_tenants=1'
            },
            {
                'method': 'GET',
                'path': '/share-networks/detail?all_tenants=1'
            }
        ],
        deprecated_rule=deprecated_share_network_get_all,
        deprecated_reason=DEPRECATED_REASON,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
]


def list_rules():
    return share_network_policies
