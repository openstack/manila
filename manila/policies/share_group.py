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


BASE_POLICY_NAME = 'share_group:%s'


share_group_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.RULE_DEFAULT,
        description="Create share group.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-groups'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.RULE_DEFAULT,
        description="Get details of a share group.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-groups/{share_group_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.RULE_DEFAULT,
        description="Get all share groups.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-groups'
            },
            {
                'method': 'GET',
                'path': '/share-groups/detail'
            },
            {
                'method': 'GET',
                'path': '/share-groups?{query}'
            },
            {
                'method': 'GET',
                'path': '/share-groups/detail?{query}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.RULE_DEFAULT,
        description="Update share group.",
        operations=[
            {
                'method': 'PUT',
                'path': '/share-groups/{share_group_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_DEFAULT,
        description="Delete share group.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-groups/{share_group_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.RULE_ADMIN_API,
        description="Force delete a share group.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-groups/{share_group_id}/action'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.RULE_ADMIN_API,
        description="Reset share group's status.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-groups/{share_group_id}/action'
            }
        ]),
]


def list_rules():
    return share_group_policies
