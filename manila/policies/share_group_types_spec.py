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


BASE_POLICY_NAME = 'share_group_types_spec:%s'


share_group_types_spec_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.RULE_ADMIN_API,
        description="Create share group type specs.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-group-types/{share_group_type_id}/group-specs'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.RULE_ADMIN_API,
        description="Get share group type specs.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-group-types/{share_group_type_id}/group-specs',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_ADMIN_API,
        description="Get details of a share group type spec.",
        operations=[
            {
                'method': 'GET',
                'path': ('/share-group-types/{share_group_type_id}/'
                         'group-specs/{key}'),
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.RULE_ADMIN_API,
        description="Update a share group type spec.",
        operations=[
            {
                'method': 'PUT',
                'path': ('/share-group-types/{share_group_type_id}'
                         '/group-specs/{key}'),
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_ADMIN_API,
        description="Delete a share group type spec.",
        operations=[
            {
                'method': 'DELETE',
                'path': ('/share-group-types/{share_group_type_id}/'
                         'group-specs/{key}'),
            }
        ]),
]


def list_rules():
    return share_group_types_spec_policies
