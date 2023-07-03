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


BASE_POLICY_NAME = 'share_export_location:%s'

DEPRECATED_REASON = """
The share export location API now support system scope and default roles.
"""

deprecated_export_location_index = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'index',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_export_location_show = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'show',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since=versionutils.deprecated.WALLABY
)
deprecated_update_export_location_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2024.2/Dalmatian'
)
deprecated_delete_export_location_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'delete_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2024.2/Dalmatian'
)
deprecated_get_export_location_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'get_metadata',
    check_str=base.RULE_DEFAULT,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since='2024.2/Dalmatian'
)
deprecated_update_admin_only_metadata = policy.DeprecatedRule(
    name=BASE_POLICY_NAME % 'update_admin_only_metadata',
    check_str=base.RULE_ADMIN_API,
    deprecated_reason=DEPRECATED_REASON,
    deprecated_since="2024.2/Dalmatian"
)


share_export_location_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get all export locations of a given share.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares/{share_id}/export_locations',
            }
        ],
        deprecated_rule=deprecated_export_location_index
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description="Get details about the requested export location.",
        operations=[
            {
                'method': 'GET',
                'path': ('/shares/{share_id}/export_locations/'
                         '{export_location_id}'),
            }
        ],
        deprecated_rule=deprecated_export_location_show
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update_metadata',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Update share export location metadata.",
        operations=[
            {
                'method': 'PUT',
                'path': ('/shares/{share_id}/export_locations/'
                         '{export_location_id}/metadata'),
            },
            {
                'method': 'POST',
                'path': ('/shares/{share_id}/export_locations/'
                         '{export_location_id}/metadata/{key}')
            },
            {
                'method': 'POST',
                'path': ('/shares/{share_id}/export_locations/'
                         '{export_location_id}/metadata'),
            },
        ],
        deprecated_rule=deprecated_update_export_location_metadata
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete_metadata',
        check_str=base.ADMIN_OR_PROJECT_MEMBER,
        scope_types=['project'],
        description="Delete share export location metadata",
        operations=[
            {
                'method': 'DELETE',
                'path': ('/shares/{share_id}/export_locations/'
                         '{export_location_id}/metadata/{key}')
            },
        ],
        deprecated_rule=deprecated_delete_export_location_metadata
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_metadata',
        check_str=base.ADMIN_OR_PROJECT_READER,
        scope_types=['project'],
        description='Get share export location metadata',
        operations=[
            {
                'method': "GET",
                'path': ('/shares/{share_id}/export_locations/'
                         '{export_location_id}/metadata')
            },
            {
                'method': 'GET',
                'path': ('/shares/{share_id}/export_locations/'
                         '{export_location_id}/metadata/{key}')
            },
        ],
        deprecated_rule=deprecated_get_export_location_metadata
    ),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update_admin_only_metadata',
        check_str=base.ADMIN,
        scope_types=['project'],
        description=(
            "Update metadata items that are considered \"admin only\" "
            "by the service."),
        operations=[
            {
                'method': 'PUT',
                'path': '/shares/{share_id}/export_locations/'
                        '{export_location_id}/metadata',
            }
        ],
        deprecated_rule=deprecated_update_admin_only_metadata
    ),
]


def list_rules():
    return share_export_location_policies
