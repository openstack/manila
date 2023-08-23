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


# This check string is reserved for actions that require the highest level of
# authorization across projects to operate the deployment. They're allowed to
# create, read, update, or delete any system-wide resource such as
# share types, share group types, storage pools, etc. They can also operate on
# project-specific resources where applicable (e.g., cleaning up shares or
# snapshots).
ADMIN = 'rule:context_is_admin'

# This check string is reserved for actions performed by a "service" or the
# "admin" super user. Service users act on behalf of other users and can
# perform privileged service-specific actions.
ADMIN_OR_SERVICE = 'rule:admin_or_service_api'


# This check string is the primary use case for typical end-users, who are
# working with resources that belong within a project (e.g., managing shares or
# share replicas). These users don't require all the authorization that
# administrators typically have.
PROJECT_MEMBER = 'rule:project-member'

# This check string should only be used to protect read-only project-specific
# resources. It should not be used to protect APIs that make writable changes
# (e.g., updating a share or snapshot). This persona is useful for someone who
# needs access for auditing or even support.
PROJECT_READER = 'rule:project-reader'

# This check string should used to protect user specific resources such as
# resource locks, or access rule restrictions. Users are expendable
# resources, so ensure that other resources can also perform actions to
# avoid orphan resources when users are decommissioned.
OWNER_USER = 'rule:owner-user'

ADMIN_OR_PROJECT_MEMBER = f'({ADMIN}) or ({PROJECT_MEMBER})'
ADMIN_OR_PROJECT_READER = f'({ADMIN}) or ({PROJECT_READER})'
ADMIN_OR_SERVICE_OR_PROJECT_READER = (f'({ADMIN_OR_SERVICE}) or '
                                      f'({PROJECT_READER})')
ADMIN_OR_SERVICE_OR_PROJECT_MEMBER = (f'({ADMIN_OR_SERVICE}) or '
                                      f'({PROJECT_MEMBER})')
ADMIN_OR_SERVICE_OR_OWNER_USER = f'({OWNER_USER} or {ADMIN_OR_SERVICE})'

# Old, "unscoped", deprecated check strings to be removed. Do not use these
# in default RBAC any longer. These can be removed after "enforce_scope"
# defaults to True in oslo.policy
RULE_ADMIN_OR_OWNER = 'rule:admin_or_owner'
RULE_ADMIN_OR_OWNER_USER = 'rule:admin_or_owner_user'
RULE_ADMIN_API = 'rule:admin_api'
RULE_DEFAULT = 'rule:default'

deprecation_msg = ("The `context_is_admin` check is superseded by more "
                   "specific check strings that consume project "
                   "scope attributes from keystone tokens.")
DEPRECATED_CONTEXT_IS_ADMIN = policy.DeprecatedRule(
    name='context_is_admin',
    check_str='role:admin',
    deprecated_reason=deprecation_msg,
    deprecated_since=versionutils.deprecated.WALLABY
)

rules = [
    # ***Default OpenStack scoped personas*** #
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
    policy.RuleDefault(
        name='owner-user',
        check_str='user_id:%(user_id)s and '
                  'project_id:%(project_id)s',
        description='Project scoped user that owns a user specific resource',
        scope_types=['project']),
    policy.RuleDefault(
        "admin_or_service_api",
        "role:admin or role:service",
        description="A service user or an administrator user.",
        scope_types=['project'],
    ),

    # ***Special personas for Manila*** #
    policy.RuleDefault(
        name='context_is_admin',
        check_str='role:admin',
        description='Privileged users checked via "context.is_admin"',
        deprecated_rule=DEPRECATED_CONTEXT_IS_ADMIN,
        scope_types=['project']),

    policy.RuleDefault(
        name='context_is_host_admin',
        check_str='role:admin and '
                  'project_id:%(project_id)s',
        description='Privileged user who can select host during scheduling',
        scope_types=['project']),

    # ***Legacy/deprecated unscoped rules*** #
    # can be removed after "enforce_scope" defaults to True in oslo.policy
    policy.RuleDefault(
        name='admin_or_owner',
        check_str='is_admin:True or project_id:%(project_id)s',
        description='Administrator or Member of the project'),
    policy.RuleDefault(
        name='admin_or_owner_user',
        check_str='is_admin:True or '
                  'project_id:%(project_id)s and user_id:%(user_id)s',
        description='Administrator or owner user of a resource'),
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
