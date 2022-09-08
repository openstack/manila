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


BASE_POLICY_NAME = 'scheduler_stats:pools:%s'

DEPRECATED_REASON = """
The storage pool statistics API now support system scope and default roles.
"""

deprecated_pool_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_pool_detail = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'detail',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


scheduler_stats_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get information regarding backends "
                    "(and storage pools) known to the scheduler.",
        operations=[
            {
                'method': 'GET',
                'path': '/scheduler-stats/pools?{query}'
            }
        ],
        deprecated_rule=deprecated_pool_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'detail',
        check_str=base.ADMIN,
        scope_types=['project'],
        description="Get detailed information regarding backends "
                    "(and storage pools) known to the scheduler.",
        operations=[
            {
                'method': 'GET',
                'path': '/scheduler-stats/pools/detail?{query}'
            },
        ],
        deprecated_rule=deprecated_pool_detail
    ),
]


def list_rules():
    return scheduler_stats_policies
