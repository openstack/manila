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

BASE_POLICY_NAME = 'share_network:%s'


share_network_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.RULE_DEFAULT,
        description="Create share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_DEFAULT,
        description="Get details of a share network.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks/{share_network_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.RULE_DEFAULT,
        description="Get all share networks.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks'
            },
            {
                'method': 'GET',
                'path': '/share-networks?{query}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'detail',
        check_str=base.RULE_DEFAULT,
        description="Get details of share networks .",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks/detail?{query}'
            },
            {
                'method': 'GET',
                'path': '/share-networks/detail'
            },
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.RULE_DEFAULT,
        description="Update a share network.",
        operations=[
            {
                'method': 'PUT',
                'path': '/share-networks/{share_network_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_DEFAULT,
        description="Delete a share network.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-networks/{share_network_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'add_security_service',
        check_str=base.RULE_DEFAULT,
        description="Add security service to share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'remove_security_service',
        check_str=base.RULE_DEFAULT,
        description="Remove security service from share network.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-networks/{share_network_id}/action'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all_share_networks',
        check_str=base.RULE_ADMIN_API,
        description="Get share networks belonging to all projects.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-networks?all_tenants=1'
            },
            {
                'method': 'GET',
                'path': '/share-networks/detail?all_tenants=1'
            }
        ]),
]


def list_rules():
    return share_network_policies
