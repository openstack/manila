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


BASE_POLICY_NAME = 'share_snapshot:%s'

DEPRECATED_REASON = """
The share snapshot API now supports scope and default roles.
"""

deprecated_snapshot_get = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_snapshot',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_get_all = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_all_snapshots',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_force_delete = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'force_delete',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_manage = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'manage_snapshot',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_unmanage = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'unmanage_snapshot',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_reset_status = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_status',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_access_list = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'access_list',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_allow_access = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'allow_access',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_deny_access = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'deny_access',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_update_snapshot_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='ZED'
)
deprecated_delete_snapshot_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='ZED'
)
deprecated_get_snapshot_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='ZED'
)


share_snapshot_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_snapshot',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get share snapshot.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshots/{snapshot_id}'
            }
        ],
        deprecated_rule=deprecated_snapshot_get
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all_snapshots',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all share snapshots.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshots?{query}'
            },
            {
                'method': 'GET',
                'path': '/snapshots/detail?{query}'
            }
        ],
        deprecated_rule=deprecated_snapshot_get_all
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Force Delete a share snapshot.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/snapshots/{snapshot_id}'
            }
        ],
        deprecated_rule=deprecated_snapshot_force_delete
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'manage_snapshot',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Manage share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/manage'
            }
        ],
        deprecated_rule=deprecated_snapshot_manage
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'unmanage_snapshot',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Unmanage share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/action'
            }
        ],
        deprecated_rule=deprecated_snapshot_unmanage
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset status.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/action',
            }
        ],
        deprecated_rule=deprecated_snapshot_reset_status
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'access_list',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="List access rules of a share snapshot.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshots/{snapshot_id}/access-list'
            }
        ],
        deprecated_rule=deprecated_snapshot_access_list
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'allow_access',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Allow access to a share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/action'
            }
        ],
        deprecated_rule=deprecated_snapshot_allow_access
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'deny_access',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Deny access to a share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/action'
            }
        ],
        deprecated_rule=deprecated_snapshot_deny_access
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update_metadata',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update snapshot metadata.",
        operations=[
            {
                'method': 'PUT',
                'path': '/snapshots/{snapshot_id}/metadata',
            },
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/metadata/{key}',
            },
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/metadata',
            },
        ],
        deprecated_rule=deprecated_update_snapshot_metadata
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete_metadata',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete snapshot metadata.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/snapshots/{snapshot_id}/metadata/{key}',
            }
        ],
        deprecated_rule=deprecated_delete_snapshot_metadata
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_metadata',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get snapshot metadata.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshots/{snapshot_id}/metadata',
            },
            {
                'method': 'GET',
                'path': '/snapshots/{snapshot_id}/metadata/{key}',
            }
        ],
        deprecated_rule=deprecated_get_snapshot_metadata
    ),
]


def list_rules():
    return share_snapshot_policies
