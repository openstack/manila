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


BASE_POLICY_NAME = 'share_export_location:%s'


share_export_location_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.RULE_DEFAULT,
        description="Get all export locations of a given share.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares/{share_id}/export_locations',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_DEFAULT,
        description="Get details about the requested export location.",
        operations=[
            {
                'method': 'GET',
                'path': ('/shares/{share_id}/export_locations/'
                         '{export_location_id}'),
            }
        ]),
]


def list_rules():
    return share_export_location_policies
