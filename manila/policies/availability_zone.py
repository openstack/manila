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


BASE_POLICY_NAME = 'availability_zone:%s'

DEPRECATED_REASON = """
The availability zone API now supports scope and default roles.
"""

deprecated_get_availability_zone = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


availability_zone_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all storage availability zones.",
        operations=[
            {
                'method': 'GET',
                'path': '/os-availability-zone',
            },
            {
                'method': 'GET',
                'path': '/availability-zone',
            },
        ],
        deprecated_rule=deprecated_get_availability_zone
    ),
]


def list_rules():
    return availability_zone_policies
