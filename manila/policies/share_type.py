# Copyright (c) 2017 Huawei Technologies Co., Ltd.
# All Rights Reserved.
#
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


BASE_POLICY_NAME = 'share_type:%s'

share_type_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str=base.RULE_ADMIN_API,
        description='Create share type.',
        operations=[
            {
                'method': 'POST',
                'path': '/types',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_DEFAULT,
        description='Get share type.',
        operations=[
            {
                'method': 'GET',
                'path': '/types/{share_type_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.RULE_DEFAULT,
        description='List share types.',
        operations=[
            {
                'method': 'GET',
                'path': '/types',
            },
            {
                'method': 'GET',
                'path': '/types?is_public=all',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'default',
        check_str=base.RULE_DEFAULT,
        description='Get default share type.',
        operations=[
            {
                'method': 'GET',
                'path': '/types/default',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_ADMIN_API,
        description='Delete share type.',
        operations=[
            {
                'method': 'DELETE',
                'path': '/types/{share_type_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'list_project_access',
        check_str=base.RULE_ADMIN_API,
        description='List share type project access.',
        operations=[
            {
                'method': 'GET',
                'path': '/types/{share_type_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'add_project_access',
        check_str=base.RULE_ADMIN_API,
        description='Add share type to project.',
        operations=[
            {
                'method': 'POST',
                'path': '/types/{share_type_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'remove_project_access',
        check_str=base.RULE_ADMIN_API,
        description='Remove share type from project.',
        operations=[
            {
                'method': 'POST',
                'path': '/types/{share_type_id}/action',
            }
        ]),
]


def list_rules():
    return share_type_policies
