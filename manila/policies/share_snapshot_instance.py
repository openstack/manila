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


BASE_POLICY_NAME = 'share_snapshot_instance:%s'

DEPRECATED_REASON = """
The share snapshot instance API now supports scope and default roles.
"""

deprecated_snapshot_instance_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_instance_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_instance_detail = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'detail',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_snapshot_instance_reset_status = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'reset_status',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


share_snapshot_instance_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get share snapshot instance.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshot-instances/{snapshot_instance_id}',
            }
        ],
        deprecated_rule=deprecated_snapshot_instance_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get all share snapshot instances.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshot-instances?{query}',
            },
        ],
        deprecated_rule=deprecated_snapshot_instance_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'detail',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get details of share snapshot instances.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshot-instances/detail?{query}',
            },
        ],
        deprecated_rule=deprecated_snapshot_instance_detail
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Reset share snapshot instance's status.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshot-instances/{snapshot_instance_id}/action',
            }
        ],
        deprecated_rule=deprecated_snapshot_instance_reset_status
    ),
]


def list_rules():
    return share_snapshot_instance_policies
