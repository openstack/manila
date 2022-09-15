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
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_detail = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'detail',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_add_security_service = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'add_security_service',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_remove_security_service = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'remove_security_service',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all_share_networks',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_add_security_service_check = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'add_security_service_check',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_update_security_service = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update_security_service',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_update_security_service_check = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update_security_service_check',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_reset_status = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_status',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_share_network_subnet_create_check = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'subnet_create_check',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since="Yoga"
)


share_network_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Create share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks'
            }
        ],
        deprecated_rule=deprecated_share_network_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get details of a share network.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks/{share_network_id}'
            }
        ],
        deprecated_rule=deprecated_share_network_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all share networks under a project.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks?{query}'
            }
        ],
        deprecated_rule=deprecated_share_network_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'detail',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get details of share networks under a project.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks/detail?{query}'
            },
        ],
        deprecated_rule=deprecated_share_network_detail
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update a share network.",
        operations=[
            {
                'method': 'PUT',
                'path': '/share-networks/{share_network_id}'
            }
        ],
        deprecated_rule=deprecated_share_network_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete a share network.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-networks/{share_network_id}'
            }
        ],
        deprecated_rule=deprecated_share_network_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'add_security_service',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Add security service to share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ],
        deprecated_rule=deprecated_share_network_add_security_service
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'add_security_service_check',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Check the feasibility of add security service to a share "
                    "network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ],
        deprecated_rule=deprecated_share_network_add_security_service_check
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'remove_security_service',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Remove security service from share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ],
        deprecated_rule=deprecated_share_network_remove_security_service
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update_security_service',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update security service from share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ],
        deprecated_rule=deprecated_share_network_update_security_service
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update_security_service_check',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Check the feasibility of update a security service from "
                    "share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ],
        deprecated_rule=deprecated_share_network_update_security_service_check
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset share network`s status.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ],
        deprecated_rule=deprecated_share_network_reset_status
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all_share_networks',
        check_str=base.ADMIN,
        scope_types=['project'],
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
        deprecated_rule=deprecated_share_network_get_all
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'subnet_create_check',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Check the feasibility of create a new share network "
                    "subnet for share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ],
        deprecated_rule=deprecated_share_network_subnet_create_check
    ),
]


def list_rules():
    return share_network_policies
