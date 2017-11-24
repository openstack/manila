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


BASE_POLICY_NAME = 'share_snapshot:%s'


share_snapshot_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_snapshot',
        check_str=base.RULE_DEFAULT,
        description="Get share snapshot.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshots/{snapshot_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all_snapshots',
        check_str=base.RULE_DEFAULT,
        description="Get all share snapshots.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshots'
            },
            {
                'method': 'GET',
                'path': '/snapshots/detail'
            },
            {
                'method': 'GET',
                'path': '/snapshots?{query}'
            },
            {
                'method': 'GET',
                'path': '/snapshots/detail?{query}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.RULE_ADMIN_API,
        description="Force Delete a share snapshot.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/snapshots/{snapshot_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'manage_snapshot',
        check_str=base.RULE_ADMIN_API,
        description="Manage share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/manage'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'unmanage_snapshot',
        check_str=base.RULE_ADMIN_API,
        description="Unmanage share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/action'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.RULE_ADMIN_API,
        description="Reset status.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'access_list',
        check_str=base.RULE_DEFAULT,
        description="List access rules of a share snapshot.",
        operations=[
            {
                'method': 'GET',
                'path': '/snapshots/{snapshot_id}/access-list'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'allow_access',
        check_str=base.RULE_DEFAULT,
        description="Allow access to a share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/action'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'deny_access',
        check_str=base.RULE_DEFAULT,
        description="Deny access to a share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots/{snapshot_id}/action'
            }
        ]),
]


def list_rules():
    return share_snapshot_policies
