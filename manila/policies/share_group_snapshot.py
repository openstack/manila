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


BASE_POLICY_NAME = 'share_group_snapshot:%s'


share_group_snapshot_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.RULE_DEFAULT,
        description="Create a new share group snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-snapshots'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.RULE_DEFAULT,
        description="Get details of a share group snapshot.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-snapshots/{share_group_snapshot_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.RULE_DEFAULT,
        description="Get all share group snapshots.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-snapshots'
            },
            {
                'method': 'GET',
                'path': '/share-group-snapshots/detail'
            },
            {
                'method': 'GET',
                'path': '/share-group-snapshots/{query}'
            },
            {
                'method': 'GET',
                'path': '/share-group-snapshots/detail?{query}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.RULE_DEFAULT,
        description="Update a share group snapshot.",
        operations=[
            {
                'method': 'PUT',
                'path': '/share-group-snapshots/{share_group_snapshot_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_DEFAULT,
        description="Delete a share group snapshot.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-group-snapshots/{share_group_snapshot_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.RULE_ADMIN_API,
        description="Force delete a share group snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-snapshots/{share_group_snapshot_id}/'
                        'action'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.RULE_ADMIN_API,
        description="Reset a share group snapshot's status.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-snapshots/{share_group_snapshot_id}/'
                        'action'
            }
        ]),
]


def list_rules():
    return share_group_snapshot_policies
