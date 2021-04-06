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

RULE_ADMIN_OR_OWNER = 'rule:admin_or_owner'
RULE_ADMIN_API = 'rule:admin_api'
RULE_DEFAULT = 'rule:default'

deprecation_msg = ("The `context_is_admin` check is superseded by more "
                   "specific check strings that consume system and project "
                   "scope attributes from keystone tokens.")
DEPRECATED_CONTEXT_IS_ADMIN = policy.DeprecatedRule(
    name='context_is_admin',
    check_str='role:admin',
    deprecated_reason=deprecation_msg,
    deprecated_since=versionutils.deprecated.WALLABY
)

# Generic policy check string for system administrators. These are the people
# who need the highest level of authorization to operate the deployment.
# They're allowed to create, read, update, or delete any system-specific
# resource. They can also operate on project-specific resources where
# applicable (e.g., cleaning up shares or snapshots).
SYSTEM_ADMIN = 'rule:system-admin'

# Generic policy check string for system users who don't require all the
# authorization that system administrators typically have. This persona, or
# check string, typically isn't used by default, but it's existence it useful
# in the event a deployment wants to offload some administrative action from
# system administrator to system members.
SYSTEM_MEMBER = 'rule:system-member'

# Generic policy check string for read-only access to system-level resources.
# This persona is useful for someone who needs access for auditing or even
# support. These uses are also able to view project-specific resources where
# applicable (e.g., listing all shares in the deployment, regardless of the
# project they belong to).
SYSTEM_READER = 'rule:system-reader'

# This check string is reserved for actions that require the highest level of
# authorization on a project or resources within the project (e.g., resyncing a
# share replica).
PROJECT_ADMIN = 'rule:project-admin'

# This check string is the primary use case for typical end-users, who are
# working with resources that belong to a project (e.g., managing shares or
# share replicas).
PROJECT_MEMBER = 'rule:project-member'

# This check string should only be used to protect read-only project-specific
# resources. It should not be used to protect APIs that make writable changes
# (e.g., updating a share or snapshot).
PROJECT_READER = 'rule:project-reader'

# The following are common composite check strings that are useful for
# protecting APIs designed to operate with multiple scopes (e.g., a system
# administrator should be able to delete any share in the deployment, a
# project member should only be able to delete shares in their project).
SYSTEM_ADMIN_OR_PROJECT_ADMIN = (
    '(' + SYSTEM_ADMIN + ') or (' + PROJECT_ADMIN + ')'
)
SYSTEM_ADMIN_OR_PROJECT_MEMBER = (
    '(' + SYSTEM_ADMIN + ') or (' + PROJECT_MEMBER + ')'
)
SYSTEM_OR_PROJECT_READER = (
    '(' + SYSTEM_READER + ') or (' + PROJECT_READER + ')'
)

rules = [
    # ***Default OpenStack scoped personas*** #
    policy.RuleDefault(
        name='system-admin',
        check_str='role:admin and '
                  'system_scope:all',
        description='System scoped Administrator',
        scope_types=['system']),
    policy.RuleDefault(
        name='system-member',
        check_str='role:member and '
                  'system_scope:all',
        description='System scoped Member',
        scope_types=['system']),
    policy.RuleDefault(
        name='system-reader',
        check_str='role:reader and '
                  'system_scope:all',
        description='System scoped Reader',
        scope_types=['system']),
    policy.RuleDefault(
        name='project-admin',
        check_str='role:admin and '
                  'project_id:%(project_id)s',
        description='Project scoped Administrator',
        scope_types=['project']),
    policy.RuleDefault(
        name='project-member',
        check_str='role:member and '
                  'project_id:%(project_id)s',
        description='Project scoped Member',
        scope_types=['project']),
    policy.RuleDefault(
        name='project-reader',
        check_str='role:reader and '
                  'project_id:%(project_id)s',
        description='Project scoped Reader',
        scope_types=['project']),

    # ***Special personas for Manila*** #
    policy.RuleDefault(
        name='context_is_admin',
        check_str='rule:system-admin',
        description='Privileged users checked via "context.is_admin"',
        deprecated_rule=DEPRECATED_CONTEXT_IS_ADMIN,
        scope_types=['system']),

    # ***Legacy/deprecated unscoped rules*** #
    # can be removed after "enforce_scope" defaults to True in oslo.policy
    policy.RuleDefault(
        name='admin_or_owner',
        check_str='is_admin:True or project_id:%(project_id)s',
        description='Administrator or Member of the project'),
    policy.RuleDefault(
        name='default',
        check_str=RULE_ADMIN_OR_OWNER,
        description='Default rule for most non-Admin APIs'),
    policy.RuleDefault(
        name='admin_api',
        check_str='is_admin:True',
        description='Default rule for most Admin APIs.'),
]


def list_rules():
    return rules
