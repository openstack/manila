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


BASE_POLICY_NAME = 'share_group_type:%s'


share_group_type_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.RULE_ADMIN_API,
        description="Create a new share group type.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-types',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.RULE_DEFAULT,
        description="Get the list of share group types.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-types',
            },
            {
                'method': 'GET',
                'path': '/share-group-types?is_public=all',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_DEFAULT,
        description="Get details regarding the specified share group type.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-types/{share_group_type_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'default',
        check_str=base.RULE_DEFAULT,
        description="Get the default share group type.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-types/default',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_ADMIN_API,
        description="Delete an existing group type.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-group-types/{share_group_type_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'list_project_access',
        check_str=base.RULE_ADMIN_API,
        description="Get project access by share group type.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-types/{share_group_type_id}/access',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'add_project_access',
        check_str=base.RULE_ADMIN_API,
        description="Allow project to use the share group type.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-types/{share_group_type_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'remove_project_access',
        check_str=base.RULE_ADMIN_API,
        description="Deny project access to use the share group type.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-types/{share_group_type_id}/action',
            }
        ]),
]


def list_rules():
    return share_group_type_policies
