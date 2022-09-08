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

from oslo_log import versionutils
from oslo_policy import policy

from manila.policies import base


BASE_POLICY_NAME = 'share_instance_export_location:%s'

DEPRECATED_REASON = """
The share instance export location API now supports scope and default roles.
"""

deprecated_instance_export_location_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_instance_export_location_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)


share_export_location_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Return data about the requested export location.',
        operations=[
            {
                'method': 'POST',
                'path': ('/share_instances/{share_instance_id}/'
                         'export_locations'),
            }
        ],
        deprecated_rule=deprecated_instance_export_location_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN,
        scope_types=['project'],
        description='Return data about the requested export location.',
        operations=[
            {
                'method': 'GET',
                'path': ('/share_instances/{share_instance_id}/'
                         'export_locations/{export_location_id}'),
            }
        ],
        deprecated_rule=deprecated_instance_export_location_show
    ),
]


def list_rules():
    return share_export_location_policies
