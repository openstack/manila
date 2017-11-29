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


BASE_POLICY_NAME = 'message:%s'


message_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.RULE_DEFAULT,
        description="Get details of a given message.",
        operations=[
            {
                'method': 'GET',
                'path': '/messages/{message_id}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.RULE_DEFAULT,
        description="Get all messages.",
        operations=[
            {
                'method': 'GET',
                'path': '/messages'
            },
            {
                'method': 'GET',
                'path': '/messages?{query}'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_DEFAULT,
        description="Delete a message.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/messages/{message_id}'
            }
        ]),
]


def list_rules():
    return message_policies
