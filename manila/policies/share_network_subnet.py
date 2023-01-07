# Copyright 2019 NetApp, Inc.
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

BASE_POLICY_NAME = 'share_network_subnet:%s'

DEPRECATED_REASON = """
The share network subnet API now supports scope and default roles.
"""

deprecated_subnet_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_subnet_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_subnet_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_subnet_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_update_subnet_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='ANTELOPE'
)
deprecated_delete_subnet_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='ANTELOPE'
)
deprecated_get_subnet_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='ANTELOPE'
)


share_network_subnet_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Create a new share network subnet.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/subnets'
            }
        ],
        deprecated_rule=deprecated_subnet_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete a share network subnet.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-networks/{share_network_id}/subnets/'
                        '{share_network_subnet_id}'
            }
        ],
        deprecated_rule=deprecated_subnet_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Shows a share network subnet.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks/{share_network_id}/subnets/'
                        '{share_network_subnet_id}'
            }
        ],
        deprecated_rule=deprecated_subnet_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all share network subnets.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks/{share_network_id}/subnets'
            }
        ],
        deprecated_rule=deprecated_subnet_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update_metadata',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['system', 'project'],
        description="Update share network subnet metadata.",
        operations=[
            {
                'method': 'PUT',
                'path': '/share-networks/{share_network_id}/subnets/'
                        '{share_network_subnet_id}/metadata',
            },
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/subnets/'
                        '{share_network_subnet_id}/metadata/{key}',
            },
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/subnets/'
                        '{share_network_subnet_id}/metadata',
            },
        ],
        deprecated_rule=deprecated_update_subnet_metadata
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete_metadata',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['system', 'project'],
        description="Delete share network subnet metadata.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-networks/{share_network_id}/subnets/'
                        '{share_network_subnet_id}/metadata/{key}',
            }
        ],
        deprecated_rule=deprecated_delete_subnet_metadata
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_metadata',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['system', 'project'],
        description="Get share network subnet metadata.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks/{share_network_id}/subnets/'
                        '{share_network_subnet_id}/metadata',
            },
            {
                'method': 'GET',
                'path': '/share-networks/{share_network_id}/subnets/'
                        '{share_network_subnet_id}/metadata/{key}',
            }
        ],
        deprecated_rule=deprecated_get_subnet_metadata
    ),
]


def list_rules():
    return share_network_subnet_policies
