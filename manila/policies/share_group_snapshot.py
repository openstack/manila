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


BASE_POLICY_NAME = 'share_group_snapshot:%s'

DEPRECATED_REASON = """
The share group snapshots API now supports scope and default roles.
"""

deprecated_group_snapshot_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_group_snapshot_get = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_group_snapshot_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_group_snapshot_update = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_group_snapshot_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_group_snapshot_force_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'force_delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_group_snapshot_reset_status = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_status',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


share_group_snapshot_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Create a new share group snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-snapshots'
            }
        ],
        deprecated_rule=deprecated_group_snapshot_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get details of a share group snapshot.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-snapshots/{share_group_snapshot_id}'
            }
        ],
        deprecated_rule=deprecated_group_snapshot_get
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all share group snapshots.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-snapshots?{query}'
            },
            {
                'method': 'GET',
                'path': '/share-group-snapshots/detail?{query}'
            }
        ],
        deprecated_rule=deprecated_group_snapshot_get_all
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update a share group snapshot.",
        operations=[
            {
                'method': 'PUT',
                'path': '/share-group-snapshots/{share_group_snapshot_id}'
            }
        ],
        deprecated_rule=deprecated_group_snapshot_update
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete a share group snapshot.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-group-snapshots/{share_group_snapshot_id}'
            }
        ],
        deprecated_rule=deprecated_group_snapshot_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Force delete a share group snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-snapshots/{share_group_snapshot_id}/'
                        'action'
            }
        ],
        deprecated_rule=deprecated_group_snapshot_force_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset a share group snapshot's status.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-snapshots/{share_group_snapshot_id}/'
                        'action'
            }
        ],
        deprecated_rule=deprecated_group_snapshot_reset_status
    ),
]


def list_rules():
    return share_group_snapshot_policies
