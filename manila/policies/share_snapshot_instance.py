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


BASE_POLICY_NAME = 'share_snapshot_instance:%s'


share_snapshot_instance_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_ADMIN_API,
        description="Get share snapshot instance.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshot-instances/{snapshot_instance_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.RULE_ADMIN_API,
        description="Get all share snapshot instances.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshot-instances',
            },
            {
                'method': 'GET',
                'path': '/snapshot-instances?{query}',
            },
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'detail',
        check_str=base.RULE_ADMIN_API,
        description="Get details of share snapshot instances.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshot-instances/detail',
            },
            {
                'method': 'GET',
                'path': '/snapshot-instances/detail?{query}',
            },
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.RULE_ADMIN_API,
        description="Reset share snapshot instance's status.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshot-instances/{snapshot_instance_id}/action',
            }
        ]),
]


def list_rules():
    return share_snapshot_instance_policies
