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


BASE_POLICY_NAME = 'share_replica:%s'

share_replica_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.RULE_DEFAULT,
        description="Create share replica.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.RULE_DEFAULT,
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
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_DEFAULT,
        description="Get details of a share replica.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-replicas/{share_replica_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_DEFAULT,
        description="Delete a share replica.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-replicas/{share_replica_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.RULE_ADMIN_API,
        description="Force delete a share replica.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'promote',
        check_str=base.RULE_DEFAULT,
        description="Promote a non-active share replica to active.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'resync',
        check_str=base.RULE_ADMIN_API,
        description="Resync a share replica that is out of sync.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_replica_state',
        check_str=base.RULE_ADMIN_API,
        description="Reset share replica's replica_state attribute.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.RULE_ADMIN_API,
        description="Reset share replica's status.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-replicas/{share_replica_id}/action',
            }
        ]),
]


def list_rules():
    return share_replica_policies
