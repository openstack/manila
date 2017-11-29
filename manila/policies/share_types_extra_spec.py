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


BASE_POLICY_NAME = 'share_types_extra_spec:%s'

share_types_extra_spec_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.RULE_ADMIN_API,
        description="Create share type extra spec.",
        operations=[
            {
                'method': 'POST',
                'path': '/types/{share_type_id}/extra_specs',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_ADMIN_API,
        description="Get share type extra specs of a given share type.",
        operations=[
            {
                'method': 'GET',
                'path': '/types/{share_type_id}/extra_specs',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.RULE_ADMIN_API,
        description="Get details of a share type extra spec.",
        operations=[
            {
                'method': 'GET',
                'path': '/types/{share_type_id}/extra_specs/{extra_spec_id}',
            },
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.RULE_ADMIN_API,
        description="Update share type extra spec.",
        operations=[
            {
                'method': 'PUT',
                'path': '/types/{share_type_id}/extra_specs',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_ADMIN_API,
        description="Delete share type extra spec.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/types/{share_type_id}/extra_specs/{key}',
            }
        ]),
]


def list_rules():
    return share_types_extra_spec_policies
