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


BASE_POLICY_NAME = 'share_replica:%s'

DEPRECATED_REASON = """
The share replica API now supports scope and default roles.
"""

deprecated_replica_create = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'create',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_replica_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_replica_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_replica_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_replica_force_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'force_delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_replica_promote = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'promote',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_replica_resync = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'resync',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_replica_reset_state = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_replica_state',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_replica_reset_status = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_status',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


share_replica_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Create share replica.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas',
            }
        ],
        deprecated_rule=deprecated_replica_create
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all share replicas.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-replicas',
            },
            {
                'method': 'GET',
                'path': '/share-replicas/detail',
            },
            {
                'method': 'GET',
                'path': '/share-replicas/detail?share_id={share_id}',
            }
        ],
        deprecated_rule=deprecated_replica_get_all
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get details of a share replica.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-replicas/{share_replica_id}',
            }
        ],
        deprecated_rule=deprecated_replica_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete a share replica.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-replicas/{share_replica_id}',
            }
        ],
        deprecated_rule=deprecated_replica_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Force delete a share replica.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ],
        deprecated_rule=deprecated_replica_force_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'promote',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Promote a non-active share replica to active.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ],
        deprecated_rule=deprecated_replica_promote
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'resync',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Resync a share replica that is out of sync.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ],
        deprecated_rule=deprecated_replica_resync
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_replica_state',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset share replica's replica_state attribute.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ],
        deprecated_rule=deprecated_replica_reset_state
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset share replica's status.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ],
        deprecated_rule=deprecated_replica_reset_status
    ),
]


def list_rules():
    return share_replica_policies
