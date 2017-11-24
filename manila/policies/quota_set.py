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


BASE_POLICY_NAME = 'quota_set:%s'


quota_set_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.RULE_ADMIN_API,
        description=("Update the quotas for a project/user and/or share "
                     "type."),
        operations=[
            {
                'method': 'PUT',
                'path': '/quota-sets/{tenant_id}'
            },
            {
                'method': 'PUT',
                'path': '/quota-sets/{tenant_id}?user_id={user_id}'
            },
            {
                'method': 'PUT',
                'path': '/quota-sets/{tenant_id}?share_type={share_type_id}'
            },
            {
                'method': 'PUT',
                'path': '/os-quota-sets/{tenant_id}'
            },
            {
                'method': 'PUT',
                'path': '/os-quota-sets/{tenant_id}?user_id={user_id}'
            },
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_DEFAULT,
        description="List the quotas for a tenant/user.",
        operations=[
            {
                'method': 'GET',
                'path': '/quota-sets/{tenant_id}/defaults'
            },
            {
                'method': 'GET',
                'path': '/os-quota-sets/{tenant_id}/defaults'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_ADMIN_API,
        description=("Delete quota for a tenant/user or "
                     "tenant/share-type. The quota will revert back to "
                     "default (Admin only)."),
        operations=[
            {
                'method': 'DELETE',
                'path': '/quota-sets/{tenant_id}'
            },
            {
                'method': 'DELETE',
                'path': '/quota-sets/{tenant_id}?user_id={user_id}'
            },
            {
                'method': 'DELETE',
                'path': '/quota-sets/{tenant_id}?share_type={share_type_id}'
            },
            {
                'method': 'DELETE',
                'path': '/os-quota-sets/{tenant_id}'
            },
            {
                'method': 'DELETE',
                'path': '/os-quota-sets/{tenant_id}?user_id={user_id}'
            },
        ]),
]


def list_rules():
    return quota_set_policies
