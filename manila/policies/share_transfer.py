# Copyright (c) 2022 China Telecom Digital Intelligence.
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


BASE_POLICY_NAME = 'share_transfer:%s'

DEPRECATED_REASON = """
The transfer API now supports system scope and default roles.
"""

deprecated_share_transfer_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since="Antelope"
)
deprecated_share_transfer_get_all_tenant = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all_tenant',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since="Antelope"
)
deprecated_share_transfer_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since="Antelope"
)
deprecated_share_transfer_get = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since="Antelope"
)
deprecated_share_transfer_accept = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'accept',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since="Antelope"
)
deprecated_share_transfer_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since="Antelope"
)


share_transfer_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.ADMIN_OR_PROJECT_READER,
        description="List share transfers.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-transfers'
            },
            {
                'method': 'GET',
                'path': '/share-transfers/detail'
            }
        ],
        deprecated_rule=deprecated_share_transfer_get_all
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all_tenant',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="List share transfers with all tenants.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-transfers'
            },
            {
                'method': 'GET',
                'path': '/share-transfers/detail'
            }
        ],
        deprecated_rule=deprecated_share_transfer_get_all_tenant
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description="Create a share transfer.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-transfers'
            }
        ],
        deprecated_rule=deprecated_share_transfer_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.ADMIN_OR_PROJECT_READER,
        description="Show one specified share transfer.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-transfers/{transfer_id}'
            }
        ],
        deprecated_rule=deprecated_share_transfer_get
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'accept',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description="Accept a share transfer.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-transfers/{transfer_id}/accept'
            }
        ],
        deprecated_rule=deprecated_share_transfer_accept
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        description="Delete share transfer.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-transfers/{transfer_id}'
            }
        ],
        deprecated_rule=deprecated_share_transfer_delete
    ),
]


def list_rules():
    return share_transfer_policies
